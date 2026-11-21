# =============================================================================
# ID:       WN-44
# NAME:     Windows change watch
# ROLE:     Windows / AD  (wave 2 - start it once the box is hardened)
# KIND:     readonly - changes nothing on the host
# VERSION:  1.0.0
#
# PURPOSE
#   Takes a baseline of the places red teams use to get back in, then checks
#   again - once, or every N seconds - and raises one alert per change, in
#   plain words, worst first.  The Windows twin of LX-40.
#     users      accounts added, deleted, enabled (domain accounts on a DC)
#     admins     who was added to Administrators, Remote Desktop Users, or
#                (on a DC) Domain / Enterprise / Schema Admins
#     services   new services, a service's program changed, set to disabled
#     running    a running service stopped (a scored one, the event log,
#                Defender or the firewall: HIGH)
#     tasks      scheduled tasks added or their command changed
#     runkeys    Run / RunOnce values (machine and logged-on users)
#     ports      new listening ports with the program (a shell: HIGH), and
#                ports nothing listens on any more
#     shares     shared folders added or changed
#     security   the firewall profiles, Defender real-time protection,
#                WDigest, sticky keys: turned off is HIGH
#     wmi        WMI event subscriptions (a favourite fileless backdoor)
#     ifeo       a "debugger" set on a program
#     hosts      the hosts file changed
#     web        pages added or changed in the IIS site folders
#     events     from the event logs since the last check: a log cleared,
#                a service installed, a task created, an account created or
#                added to a group, a Remote Desktop logon from a new address
#   Each change is reported once.  changes-since-baseline.txt in the state
#   folder always holds the full list of what differs from the baseline.
#
#   QUESTIONS (Enter takes the default in capitals; a parameter answers each):
#     use the existing baseline, or take a new one   -Baseline / -UseBaseline
#     seconds between checks (0 = once)              -Loop N / -Once
#     read the event logs too?                       -NoEvents (Enter = yes)
#     your team's addresses (never alerted)          -Team 'A B'
#     also write the alerts to a file (a share)      -AlertTo FILE
#   -Batch, or no console: the defaults, and ONE check (no loop unless -Loop).
#
# USAGE
#   powershell -NoProfile -ExecutionPolicy Bypass -File WN-44-change-watch.ps1               asks, then watches
#   powershell ... WN-44-change-watch.ps1 -Batch                                            one check
#   powershell ... WN-44-change-watch.ps1 -Loop 60 -Team 10.0.0.5 -AlertTo \\10.0.0.9\alerts\borgar.txt
#   powershell ... WN-44-change-watch.ps1 -Accept                                           your own changes become the baseline
#   Run in an elevated window (the Security log and other accounts' keys need it).
#
# OPTIONS
#   -Baseline / -Accept   take a new baseline (after your own changes)
#   -UseBaseline       keep the existing baseline (no question)
#   -Loop N            check every N seconds (10 or more) until Ctrl-C
#   -Once              check once and stop
#   -Count N           with -Loop: stop after N checks
#   -NoEvents          do not read the event logs
#   -Team 'A B'        team addresses: their Remote Desktop logons are never alerted
#   -AlertTo FILE      also append each alert line to FILE (a share off the box)
#   -State DIR         where the baseline lives (default <out>\watch-<host>)
#   -NoColor           no colours
#   Common options (-Out, -Protected, -Quiet, -DebugLog) come from the library.
#
# OUTPUTS
#   <out>\changewatch-N\   this run: output.txt, alerts.txt (a table),
#                          summary.txt, run.txt
#   <out>\watch-<host>\    the state, kept between runs:
#     baseline\, last\          the snapshots (plain text, one per section)
#     alerts.log                every alert ever: time SEVERITY section change item - detail
#     changes-since-baseline.txt  what differs from the baseline right now
#     last-check.txt, rdp-seen.txt
#
# WHAT IT CHANGES
#   Nothing on the host.  It reads the registry, WMI, files and event logs.
#
# DEPENDS ON
#   WMI, ADSI, the registry, netstat.exe, Get-WinEvent (Vista / 2008 and
#   later).  $env:BT_WN44_FAKE names a folder of stand-in snapshots (one
#   <section>.txt each, "key|detail" lines) and events.txt for the tests.
#
# TESTED ON
#   PowerShell 7 on Linux against stand-in snapshots (tests/wn44.Tests.ps1).
#   NOT yet run on real Windows: run it on a throwaway VM first.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - It sees changes, not intent: your own hardening shows up too.  After
#     changing things on purpose, run -Accept.
#   - A red team with admin rights can stop or fool this script: send the
#     alerts off the box with -AlertTo.
#   - Web pages are compared by size and time, not content.
#
# DEBUGGING
#   -DebugLog shows how many items each section found.  The snapshots in
#   baseline\ and last\ are plain text: compare them by hand.
# =============================================================================
param(
    [string]$Out, [string]$Protected, [switch]$NoProtected, [switch]$Quiet, [switch]$DebugLog,
    [switch]$Baseline, [switch]$Accept, [switch]$UseBaseline,
    [int]$Loop = -1, [switch]$Once, [int]$Count = 0,
    [switch]$NoEvents,
    [string[]]$Team = @(),
    [string]$AlertTo = '',
    [string]$State = '',
    [switch]$Help,
    [switch]$Batch,
    [switch]$NoColor
)

if ($Help) {
    Write-Host 'WN-44 Windows change watch - alerts on new accounts, admins, services, tasks, Run keys, ports, cleared logs'
    Write-Host '  -Baseline/-Accept  new baseline   -UseBaseline  keep it'
    Write-Host '  -Loop N  every N seconds   -Once   -Count N   -NoEvents'
    Write-Host '  -Team "A B"  never alerted   -AlertTo FILE  copy of each alert   -State DIR'
    Write-Host '  -Batch -NoColor -Out DIR -Protected FILE -Quiet -DebugLog'
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
if ($Accept) { $Baseline = $true }
if ($Baseline -and $UseBaseline) { Write-Host '-Baseline and -UseBaseline cannot go together'; exit 2 }
if ($Once) { $Loop = 0 }
if ($Loop -gt 0 -and $Loop -lt 10) { Write-Host '-Loop must be 10 seconds or more (or 0 for once)'; exit 2 }
$Team = @(@($Team) | Where-Object { $_ } | ForEach-Object { $_ -split '[,\s]+' } | Where-Object { $_ })
function Lc($s) { if ($null -eq $s) { return '' }; return ([string]$s).ToLower() }
function Nz($s) { if ($null -eq $s) { return '' }; return [string]$s }

# ---- Start ------------------------------------------------------------------
Initialize-Cc -Id 'WN-44' -Name 'Windows change watch' -Kind readonly -Bound $PSBoundParameters
$Fake = $env:BT_WN44_FAKE
if ($Fake) { Write-CcLog -Level WARN -Message "TEST MODE: stand-in snapshots from $Fake" }
Use-CcNumberedDir 'changewatch'
Write-CcShow -Color Cyan -Text ('WN-44 Windows change watch | host {0} | results in {1}' -f $Cc.Host, $Cc.RunDir)
Write-CcLegend -Marks @('Red=[!] HIGH', 'Yellow=[*] MED', 'DarkGray=[-] LOW', 'Green=[ok] no change')
if (-not $State) { $State = Join-Path $Cc.Out ('watch-' + $Cc.Host) }
$BaseDir = Join-Path $State 'baseline'; $LastDir = Join-Path $State 'last'
foreach ($d in @($State, $BaseDir, $LastDir)) { if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null } }
$IsDC = $false
if ($Fake) { $IsDC = Test-Path -LiteralPath (Join-Path $Fake 'is-dc') } else { $IsDC = (Get-CcOsInfo).IsDC }
$Sections = @('users', 'admins', 'services', 'running', 'tasks', 'runkeys', 'ports', 'shares', 'security', 'wmi', 'ifeo', 'hosts', 'web')

# ---- 1/3 Questions ------------------------------------------------------------------
Write-CcHeader '1/3  questions'
$haveBase = Test-Path -LiteralPath (Join-Path $BaseDir 'taken.txt')
$newBase = $false
if (-not $haveBase) { $newBase = $true; Write-CcShow -Text '  No baseline yet: one is taken now.' }
elseif ($Baseline) { $newBase = $true }
elseif (-not $UseBaseline) {
    $bt = [IO.File]::ReadAllText((Join-Path $BaseDir 'taken.txt')).Trim()
    $newBase = -not (Read-CcAsk -Question ('Use the baseline from ' + $bt + '?') -Default Y -Yes 'yes, compare against it' -No 'no, take a new one now (after your own hardening)')
}
if ($Loop -lt 0) {
    if (Test-CcCanAsk) {
        $a = Read-CcText -Question 'How often should it check?' -Default '60' -Hint 'seconds between checks, like 60; 0 = check once and stop'
        $n = 0; if (-not [int]::TryParse($a, [ref]$n) -or ($n -gt 0 -and $n -lt 10)) { Write-CcShow -Color Yellow -Text '  [*] not a number of seconds (10 or more): checking once'; $n = 0 }
        $Loop = $n
    } else { $Loop = 0; Write-CcShow -Color Cyan -Text '[?] How often should it check? 0 (no console: one check)' }
}
$Events = -not $NoEvents
if (-not $NoEvents -and -not $PSBoundParameters.ContainsKey('NoEvents')) {
    $Events = Read-CcAsk -Question 'Read the event logs too?' -Default Y -Yes 'yes: cleared logs, new services and tasks, new accounts, Remote Desktop logons' -No 'no, only compare the snapshots'
}
if ($Events -and $Team.Count -eq 0 -and -not $PSBoundParameters.ContainsKey('Team')) {
    $tf = Join-Path $State 'team.txt'; $td = ''; if (Test-Path -LiteralPath $tf) { $td = [IO.File]::ReadAllText($tf).Trim() }
    $t = Read-CcText -Question 'Your team''s addresses (their Remote Desktop logons are never alerted)?' -Default $td -Hint 'addresses separated by spaces, like 10.0.0.5 10.0.0.6'
    $Team = @($t -split '[,\s]+' | Where-Object { $_ })
}
if ($Team.Count -gt 0) { [IO.File]::WriteAllText((Join-Path $State 'team.txt'), ($Team -join ' ')) }
if (-not $AlertTo -and -not $PSBoundParameters.ContainsKey('AlertTo') -and $Loop -gt 0) {
    $AlertTo = Read-CcText -Question 'Also write each alert to a file off the box (a share)?' -Default '' -Hint 'a file, like \\10.0.0.9\alerts\borgar.txt (Enter = no)'
}

# ---- Reading (or the stand-in) --------------------------------------------------------
# Each section gives lines "key|detail", sorted.
$OddRe = '(\\users\\public\\|\\perflogs\\|\\windows\\temp\\|\\temp\\|\\tmp\\|\\appdata\\|\\downloads\\|\$recycle\.bin)'
$BadRe = '(' + (@('-enc(odedcommand)?\s', 'frombase64string', 'downloadstring', 'downloadfile', 'invoke-expression', '\biex\b', 'net\.webclient', 'invoke-webrequest', 'mshta\s+(http|vbscript|javascript)', 'certutil.*-urlcache', 'bitsadmin.*\/transfer', '-w(indowstyle)?\s+hid') -join '|') + ')'  # ps2-ok (text to look for, not a call)
$ShellNames = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'nc.exe', 'ncat.exe', 'nc64.exe', 'socat.exe', 'plink.exe', 'mshta.exe', 'rundll32.exe', 'wscript.exe', 'cscript.exe')
function L([string]$k, [string]$d) { return ($k.Replace('|', '/') + '|' + ($d -replace '[\r\n]+', ' ')) }
function R-Fake([string]$sec) { $p = Join-Path $Fake ($sec + '.txt'); if (Test-Path -LiteralPath $p) { return @([IO.File]::ReadAllLines($p) | Where-Object { $_ }) }; return @() }
# Get-Wmi CLASS [FILTER]: Get-WmiObject (Windows PowerShell), or the CIM cmdlet in PowerShell 7.
function Get-Wmi([string]$cls, [string]$flt = '') {
    if (Test-CcCommand 'Get-WmiObject') { if ($flt) { return @(Get-WmiObject -Class $cls -Filter $flt -ErrorAction SilentlyContinue) }; return @(Get-WmiObject -Class $cls -ErrorAction SilentlyContinue) }
    if ($flt) { return @(Get-CimInstance -ClassName $cls -Filter $flt -ErrorAction SilentlyContinue) }; return @(Get-CimInstance -ClassName $cls -ErrorAction SilentlyContinue)  # ps2-ok (PowerShell 7 only)
}
function R-Users {
    $o = @()
    if ($IsDC) {
        try {
            $s = New-Object DirectoryServices.DirectorySearcher('(&(objectCategory=person)(objectClass=user))'); $s.PageSize = 1000
            [void]$s.PropertiesToLoad.Add('samaccountname'); [void]$s.PropertiesToLoad.Add('useraccountcontrol')
            foreach ($r in $s.FindAll()) { $u = [int]($r.Properties['useraccountcontrol'][0]); $o += L ([string]$r.Properties['samaccountname'][0]) $(if ($u -band 2) { 'disabled' } else { 'enabled' }) }
        } catch { Write-CcLog -Level WARN -Message ('domain accounts not read: ' + $_.Exception.Message) }
    } else {
        foreach ($u in @(Get-Wmi Win32_UserAccount 'LocalAccount=True')) { $o += L $u.Name $(if ($u.Disabled) { 'disabled' } else { 'enabled' }) }
    }
    return $o
}
function R-Admins {
    $o = @()
    if ($IsDC) {
        foreach ($g in @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators', 'Backup Operators', 'DnsAdmins', 'Group Policy Creator Owners')) {
            try {
                $s = New-Object DirectoryServices.DirectorySearcher(('(&(objectClass=group)(cn=' + $g + '))')); [void]$s.PropertiesToLoad.Add('member')
                $r = $s.FindOne(); if (-not $r) { continue }
                foreach ($m in @($r.Properties['member'])) { $cn = ([string]$m -replace '^CN=([^,]+),.*$', '$1'); $o += L ($g + ': ' + $cn) '' }
            } catch { }
        }
    } else {
        foreach ($g in @('Administrators', 'Remote Desktop Users')) {
            try {
                $grp = [ADSI]('WinNT://' + $env:COMPUTERNAME + '/' + $g + ',group')
                foreach ($m in @($grp.psbase.Invoke('Members'))) { $p = [string]$m.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $m, $null); $o += L ($g + ': ' + (($p -replace '^WinNT://', '') -replace '/', '\')) '' }
            } catch { }
        }
    }
    return $o
}
$script:SvcCache = $null
function Get-Svcs { if ($null -eq $script:SvcCache) { $script:SvcCache = @(Get-Wmi Win32_Service) }; return $script:SvcCache }
function R-Services { return @(Get-Svcs | ForEach-Object { L $_.Name ((Nz $_.StartMode) + ' ' + (Nz $_.PathName)) }) }
function R-Running { return @(Get-Svcs | Where-Object { $_.State -eq 'Running' } | ForEach-Object { L $_.Name 'Running' }) }
function R-Tasks {
    $root = Join-Path $env:SystemRoot 'System32\Tasks'; $o = @()
    foreach ($f in @(Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer })) {
        try { [xml]$x = [IO.File]::ReadAllText($f.FullName) } catch { continue }
        $run = @(); foreach ($e in @($x.Task.Actions.Exec)) { if ($e) { $run += ((Nz $e.Command) + ' ' + (Nz $e.Arguments)).Trim() } }
        $o += L ('\' + $f.FullName.Substring($root.Length + 1)) ($run -join ' ; ')
    }
    return $o
}
function R-RunKeys {
    $keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon')
    foreach ($h in @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' })) { $keys += ('Registry::HKEY_USERS\' + $h.PSChildName + '\Software\Microsoft\Windows\CurrentVersion\Run') }
    $o = @()
    foreach ($k in $keys) {
        $i = Get-Item -LiteralPath $k -ErrorAction SilentlyContinue; if (-not $i) { continue }
        $names = @($i.GetValueNames()); if ($k -like '*Winlogon') { $names = @('Userinit', 'Shell') }
        foreach ($v in $names) { if ($v) { $o += L (($k -replace '^Registry::', '' -replace '^HKLM:', 'HKLM') + '\' + $v) ([string]$i.GetValue($v)) } }
    }
    return $o
}
function R-Ports {
    $procs = @{}; foreach ($p in @(Get-Wmi Win32_Process)) { $procs[[string]$p.ProcessId] = [string]$p.Name }
    $o = @(); $seen = @{}
    foreach ($l in @(Invoke-CcProgram -FilePath 'netstat.exe' -Arguments @('-ano'))) {
        $f = @(([string]$l).Trim() -split '\s+'); if ($f.Count -lt 5 -or $f[0] -ne 'TCP') { continue }
        $ri = $f[2].LastIndexOf(':'); if ($ri -lt 0 -or $f[2].Substring($ri + 1) -ne '0') { continue }
        $li = $f[1].LastIndexOf(':'); $port = $f[1].Substring($li + 1); $addr = $f[1].Substring(0, $li)
        if ($addr -like '127.*' -or $addr -eq '[::1]') { continue }
        $n = $procs[$f[4]]; if ($f[4] -eq '4') { $n = 'System' }
        if ($seen.ContainsKey($port)) { continue }; $seen[$port] = 1
        $o += L ('tcp/' + $port) (Nz $n)
    }
    return $o
}
function R-Shares { return @(Get-Wmi Win32_Share | Where-Object { $_.Name -notmatch '^(ADMIN\$|IPC\$|[A-Z]\$)$' } | ForEach-Object { L $_.Name (Nz $_.Path) }) }
function RegV([string]$k, [string]$n) { $v = (Get-ItemProperty -LiteralPath $k -Name $n -ErrorAction SilentlyContinue).$n; return $v }
function R-Security {
    $o = @()
    $fp = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
    foreach ($p in @(@('Domain', 'DomainProfile'), @('Private', 'StandardProfile'), @('Public', 'PublicProfile'))) { $v = RegV (Join-Path $fp $p[1]) 'EnableFirewall'; $o += L ('firewall ' + $p[0]) $(if ($v -eq 0) { 'off' } else { 'on' }) }
    $rt = RegV 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' 'DisableRealtimeMonitoring'
    $rt2 = RegV 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection' 'DisableRealtimeMonitoring'
    $o += L 'defender real-time' $(if ($rt -eq 1 -or $rt2 -eq 1) { 'off' } else { 'on' })
    $wd = RegV 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential'
    $o += L 'wdigest (passwords in memory)' $(if ($wd -eq 1) { 'off (passwords kept in memory)' } else { 'on (safe)' })
    $sk = RegV 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe' 'Debugger'
    $o += L 'sticky keys' $(if ($sk) { 'off (runs ' + $sk + ')' } else { 'on (normal)' })
    $el = @(Get-Svcs | Where-Object { $_.Name -eq 'EventLog' })
    if ($el.Count -gt 0) { $o += L 'event log service' $(if ($el[0].State -eq 'Running') { 'on' } else { 'off' }) }
    return $o
}
function R-Wmi {
    $o = @()
    try { foreach ($b in @(Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction Stop)) { $o += L ([string]$b.Consumer -replace '^.*:', '') ([string]$b.Filter -replace '^.*:', '') } } catch { }
    return $o
}
function R-Ifeo {
    $o = @(); $k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    foreach ($i in @(Get-ChildItem -LiteralPath $k -ErrorAction SilentlyContinue)) { $d = $i.GetValue('Debugger'); if ($d) { $o += L $i.PSChildName ([string]$d) } }
    return $o
}
function R-Hosts { $p = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'; if (Test-Path -LiteralPath $p) { return @(L 'hosts' (Get-CcSha256 -Path $p)) }; return @() }
function R-Web {
    $roots = @(); $ahc = Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
    if (Test-Path -LiteralPath $ahc) { try { [xml]$ax = [IO.File]::ReadAllText($ahc); foreach ($v in @($ax.SelectNodes('//virtualDirectory'))) { $roots += [Environment]::ExpandEnvironmentVariables([string]$v.physicalPath) } } catch { } }
    $o = @(); $n = 0
    foreach ($r in @($roots | Select-Object -Unique)) {
        foreach ($f in @(Get-ChildItem -LiteralPath $r -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer -and $_.Extension -match '^\.(aspx|asp|ashx|asmx|ascx|cshtml|php|jsp|config|exe|dll|ps1|bat)$' })) {
            $n++; if ($n -gt 20000) { break }
            $o += L $f.FullName ('{0} bytes, {1}' -f $f.Length, $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))
        }
    }
    return $o
}
function Snap([string]$sec) {
    if ($Fake) { return @(R-Fake $sec | Sort-Object -Unique) }
    $r = @()
    try {
        switch ($sec) {
            'users' { $r = R-Users }; 'admins' { $r = R-Admins }; 'services' { $r = R-Services }; 'running' { $r = R-Running }
            'tasks' { $r = R-Tasks }; 'runkeys' { $r = R-RunKeys }; 'ports' { $r = R-Ports }; 'shares' { $r = R-Shares }
            'security' { $r = R-Security }; 'wmi' { $r = R-Wmi }; 'ifeo' { $r = R-Ifeo }; 'hosts' { $r = R-Hosts }; 'web' { $r = R-Web }
        }
    } catch { Write-CcLog -Level WARN -Message ('section ' + $sec + ' not read: ' + $_.Exception.Message) }
    return @($r | Where-Object { $_ } | Sort-Object -Unique)
}
function Read-Snap([string]$dir, [string]$sec) { $p = Join-Path $dir ($sec + '.txt'); if (Test-Path -LiteralPath $p) { return @([IO.File]::ReadAllLines($p) | Where-Object { $_ }) }; return @() }
function Save-Snap([string]$dir, [string]$sec, $lines) { [IO.File]::WriteAllLines((Join-Path $dir ($sec + '.txt')), [string[]]@($lines)) }
function To-Map($lines) { $m = @{}; foreach ($l in $lines) { $i = $l.IndexOf('|'); if ($i -lt 0) { $m[$l] = '' } else { $m[$l.Substring(0, $i)] = $l.Substring($i + 1) } }; return $m }

# ---- How bad is each change -------------------------------------------------------------
# Rate SECTION CHANGE KEY OLD NEW -> @(severity, text) or $null (not worth an alert)
$SecSvc = @('eventlog', 'windefend', 'mpssvc', 'sense', 'wdnissvc', 'sysmon', 'sysmon64')
function Rate([string]$sec, [string]$ch, [string]$k, [string]$old, [string]$new) {
    $n = Lc $new
    switch ($sec) {
        'users' { if ($ch -eq 'added') { return @('MED', 'a new account') }; if ($ch -eq 'removed') { return @('MED', 'an account was deleted') }; if ($n -eq 'enabled') { return @('MED', 'an account was enabled') }; return @('LOW', 'an account was disabled') }
        'admins' { if ($ch -eq 'added') { return @('HIGH', 'a new member of an admin group') }; return @('MED', 'removed from an admin group') }
        'services' {
            if ($ch -eq 'added') { if ($n -match $OddRe -or $n -match $BadRe) { return @('HIGH', 'a new service from a temp or user folder') }; return @('MED', 'a new service') }
            if ($ch -eq 'removed') { return @('LOW', 'a service was removed') }
            $op = ($old -split ' ', 2); $np = ($new -split ' ', 2)
            if ($op.Count -gt 1 -and $np.Count -gt 1 -and $op[1] -ne $np[1]) { return @('HIGH', ('its program changed (was: ' + $op[1] + ')')) }
            if ($np[0] -eq 'Disabled') { return @('MED', ('set to Disabled (was ' + $op[0] + ')')) }
            return @('LOW', ('start mode ' + $op[0] + ' -> ' + $np[0]))
        }
        'running' {
            if ($ch -ne 'removed') { return $null }
            if (($SecSvc -contains (Lc $k)) -or ($script:Cc.Protected -and (Test-CcProtected -Type service -Value $k))) { return @('HIGH', 'stopped (a scored or security service): WN-50 brings it back') }
            return @('MED', 'stopped')
        }
        'tasks' { if ($ch -eq 'removed') { return @('LOW', 'a task was removed') }; if ($n -match $BadRe -or $n -match $OddRe) { return @('HIGH', $(if ($ch -eq 'added') { 'a new task that downloads, hides or runs from a temp folder' } else { 'its command changed to one that downloads, hides or runs from a temp folder' })) }; if ($ch -eq 'added') { return @('MED', 'a new scheduled task') }; return @('HIGH', 'its command changed') }
        'runkeys' { if ($ch -eq 'removed') { return @('LOW', 'removed') }; if ($ch -eq 'added') { return @('HIGH', 'starts at every logon') }; return @('HIGH', ('changed (was: ' + $old + ')')) }
        'ports' {
            if ($ch -eq 'removed') { return @('MED', ('nothing listens here any more (was ' + $old + '): a service went down?')) }
            if ($ShellNames -contains $n -or -not $n) { return @('HIGH', ('a new listener: ' + $(if ($n) { $new + ' (a shell or tunnel)' } else { 'unknown program' }))) }
            if ($ch -eq 'added') { return @('MED', ('a new listener: ' + $new)) }; return @('MED', ('now ' + $new + ' (was ' + $old + ')'))
        }
        'shares' { if ($ch -eq 'removed') { return @('LOW', 'a share was removed') }; return @('MED', ($(if ($ch -eq 'added') { 'a new share' } else { 'a share now points elsewhere (was ' + $old + ')' }))) }
        'security' { if ($n -like 'off*') { return @('HIGH', 'turned off') }; if ($ch -eq 'removed') { return @('LOW', 'no longer read') }; return @('LOW', ('now ' + $new)) }
        'wmi' { if ($ch -eq 'removed') { return @('LOW', 'a WMI subscription was removed') }; return @('HIGH', 'a new WMI event subscription (WN-42 removes it)') }
        'ifeo' { if ($ch -eq 'removed') { return @('LOW', 'a debugger was removed') }; return @('HIGH', 'runs instead of this program (WN-42 / WN-43)') }
        'hosts' { return @('MED', 'the hosts file changed: names may point elsewhere') }
        'web' { if ($ch -eq 'removed') { return @('MED', 'a page was removed') }; if ($ch -eq 'added') { return @('HIGH', 'a new page in the site: WN-16 checks it') }; return @('MED', 'a page changed: WN-16 checks it') }
    }
    return @('LOW', $ch)
}
function Diff([string]$sec, $old, $new) {
    $a = To-Map $old; $b = To-Map $new; $out = @()
    foreach ($k in $b.Keys) {
        if (-not $a.ContainsKey($k)) { $out += ,@('added', $k, '', $b[$k]) }
        elseif ($a[$k] -ne $b[$k]) { $out += ,@('changed', $k, $a[$k], $b[$k]) }
    }
    foreach ($k in $a.Keys) { if (-not $b.ContainsKey($k)) { $out += ,@('removed', $k, $a[$k], '') } }
    return $out
}

# ---- Events since the last check ------------------------------------------------------------
# -> rows @(time, kind, detail, address)
function In-Team([string]$ip) { foreach ($t in $Team) { if ($ip -eq $t) { return $true }; if ($t -match '^(\d+\.\d+\.\d+)\.0/24$' -and $ip.StartsWith($matches[1] + '.')) { return $true } }; return $false }
function EvData($e, [string]$name) { try { $x = [xml]$e.ToXml(); foreach ($d in @($x.Event.EventData.Data)) { if ($d.Name -eq $name) { return [string]$d.'#text' } } } catch { }; return '' }
function R-Events([DateTime]$since) {
    $rows = @()
    if ($Fake) {
        foreach ($l in @(R-Fake 'events')) { $p = $l -split '\|', 4; $t = [DateTime]::Parse($p[0]); if ($t -gt $since) { $rows += ,@($t, $p[1], $p[2], $(if ($p.Count -gt 3) { $p[3] } else { '' })) } }
        return $rows
    }
    $q = @(@{ LogName = 'Security'; Id = @(1102, 4720, 4728, 4732, 4756, 4698); StartTime = $since }, @{ LogName = 'System'; Id = @(104, 7045); StartTime = $since }, @{ LogName = 'Security'; Id = 4624; StartTime = $since })
    foreach ($h in $q) {
        try {
            foreach ($e in @(Get-WinEvent -FilterHashtable $h -MaxEvents 200 -ErrorAction Stop)) {
                switch ($e.Id) {
                    1102 { $rows += ,@($e.TimeCreated, 'cleared', ('the Security log was cleared by ' + (EvData $e 'SubjectUserName')), '') }
                    104 { $rows += ,@($e.TimeCreated, 'cleared', 'an event log was cleared', '') }
                    4720 { $rows += ,@($e.TimeCreated, 'account', ('account created: ' + (EvData $e 'TargetUserName') + ' by ' + (EvData $e 'SubjectUserName')), '') }
                    { $_ -eq 4728 -or $_ -eq 4732 -or $_ -eq 4756 } { $rows += ,@($e.TimeCreated, 'group', ((EvData $e 'MemberName') + ' added to ' + (EvData $e 'TargetUserName') + ' by ' + (EvData $e 'SubjectUserName')), '') }
                    4698 { $rows += ,@($e.TimeCreated, 'task', ('scheduled task created: ' + (EvData $e 'TaskName') + ' by ' + (EvData $e 'SubjectUserName')), '') }
                    7045 { $rows += ,@($e.TimeCreated, 'service', ('service installed: ' + (EvData $e 'ServiceName') + ' (' + (EvData $e 'ImagePath') + ')'), '') }
                    4624 { if ((EvData $e 'LogonType') -eq '10') { $ip = EvData $e 'IpAddress'; $rows += ,@($e.TimeCreated, 'rdp', ('Remote Desktop logon: ' + (EvData $e 'TargetDomainName') + '\' + (EvData $e 'TargetUserName') + ' from ' + $ip), $ip) } }
                }
            }
        } catch { if ($_.Exception.Message -notmatch 'No events') { Write-CcLog -Level DEBUG -Message ('events not read (' + $h.LogName + '): ' + $_.Exception.Message) } }
    }
    return $rows
}

# ---- One check ------------------------------------------------------------------------------
$alertsTab = New-CcTable -Name alerts -Columns @('time', 'severity', 'section', 'change', 'item', 'detail')
$logFile = Join-Path $State 'alerts.log'
$tot = @{ HIGH = 0; MED = 0; LOW = 0 }
function Emit([string]$sev, [string]$sec, [string]$ch, [string]$item, [string]$text) {
    $now = [DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss')
    $c = @{ HIGH = 'Red'; MED = 'Yellow'; LOW = 'DarkGray' }[$sev]; $m = @{ HIGH = '[!]'; MED = '[*]'; LOW = '[-]' }[$sev]
    Write-CcShow -Color $c -Text ('  {0} {1,-4} {2,-8} {3,-7} {4} - {5}' -f $m, $sev, $sec, $ch, $item, $text)
    $line = ('{0} {1} {2} {3} {4} - {5}' -f $now, $sev, $sec, $ch, $item, $text)
    [IO.File]::AppendAllText($logFile, $line + "`r`n")
    if ($AlertTo) { try { [IO.File]::AppendAllText($AlertTo, ($Cc.Host + ' ' + $line + "`r`n")) } catch { if (-not $script:alertWarned) { Write-CcShow -Color Yellow -Text ('  [*] could not write to ' + $AlertTo + ': ' + $_.Exception.Message); $script:alertWarned = $true } } }
    Add-CcTableRow -File $alertsTab -Values @($now, $sev, $sec, $ch, $item, $text)
    $script:tot[$sev]++
}
function Take-Baseline {
    foreach ($s in $Sections) { $l = Snap $s; Save-Snap $BaseDir $s $l; Save-Snap $LastDir $s $l; Write-CcLog -Level DEBUG -Message ('{0}: {1} items' -f $s, @($l).Count) }
    $t = [DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss')
    [IO.File]::WriteAllText((Join-Path $BaseDir 'taken.txt'), $t); [IO.File]::WriteAllText((Join-Path $State 'last-check.txt'), [DateTime]::Now.ToString('o'))
    Write-CcShow -Color Green -Text ('  [ok] baseline taken ({0}): {1}' -f $t, (($Sections | ForEach-Object { $_ + ' ' + @(Read-Snap $BaseDir $_).Count }) -join ', '))
}
function Check-Once {
    $script:SvcCache = $null
    $found = 0; $rows = @()
    foreach ($s in $Sections) {
        $new = Snap $s; $old = Read-Snap $LastDir $s
        foreach ($d in @(Diff $s $old $new)) { $r = Rate $s $d[0] $d[1] $d[2] $d[3]; if ($r) { $rows += ,@($r[0], $s, $d[0], $d[1], $r[1]) } }
        Save-Snap $LastDir $s $new
    }
    if ($Events) {
        $lc = Join-Path $State 'last-check.txt'; $since = [DateTime]::Now.AddMinutes(-15)
        if (Test-Path -LiteralPath $lc) { try { $since = [DateTime]::Parse([IO.File]::ReadAllText($lc).Trim()) } catch { } }
        $seenF = Join-Path $State 'rdp-seen.txt'; $seen = @(); if (Test-Path -LiteralPath $seenF) { $seen = @([IO.File]::ReadAllLines($seenF)) }
        foreach ($e in @(R-Events $since)) {
            $sev = @{ cleared = 'HIGH'; service = 'HIGH'; group = 'HIGH'; account = 'MED'; task = 'MED'; rdp = 'MED' }[$e[1]]; if (-not $sev) { $sev = 'LOW' }
            if ($e[1] -eq 'rdp') {
                $ip = $e[3]; if (-not $ip -or $ip -eq '-' -or (In-Team $ip) -or ($seen -contains $ip)) { continue }
                $seen += $ip; [IO.File]::AppendAllText($seenF, $ip + "`r`n")
            }
            $rows += ,@($sev, 'events', $e[1], ([DateTime]$e[0]).ToString('HH:mm:ss'), $e[2])
        }
        [IO.File]::WriteAllText($lc, [DateTime]::Now.ToString('o'))
    }
    $ord = @{ HIGH = 1; MED = 2; LOW = 3 }
    foreach ($r in @($rows | Sort-Object @{ Expression = { $ord[$_[0]] } }, @{ Expression = { $_[1] } })) { Emit $r[0] $r[1] $r[2] $r[3] $r[4]; $found++ }
    if ($found -eq 0) { Write-CcShow -Color Green -Text ('  [ok] {0} no change' -f [DateTime]::Now.ToString('HH:mm:ss')) }
    # The full picture against the baseline.
    $all = @()
    foreach ($s in $Sections) { foreach ($d in @(Diff $s (Read-Snap $BaseDir $s) (Read-Snap $LastDir $s))) { $r = Rate $s $d[0] $d[1] $d[2] $d[3]; if ($r) { $all += ('{0,-4} {1,-8} {2,-7} {3} - {4}' -f $r[0], $s, $d[0], $d[1], $r[1]) } } }
    [IO.File]::WriteAllLines((Join-Path $State 'changes-since-baseline.txt'), [string[]]@(@('Changes since the baseline of ' + [IO.File]::ReadAllText((Join-Path $BaseDir 'taken.txt')).Trim()) + @($all | Sort-Object)))
    return $found
}

# ---- 2/3 Watching ------------------------------------------------------------------------------
$checks = 0
if ($newBase) {
    Write-CcHeader '2/3  baseline'
    Take-Baseline
    if ($Loop -le 0) { $checks = 0 }
}
if (-not $newBase -or $Loop -gt 0) {
    Write-CcHeader $(if ($Loop -gt 0) { ('2/3  checking every {0} s (Ctrl-C to stop)' -f $Loop) } else { '2/3  check' })
    while ($true) {
        if (-not ($newBase -and $checks -eq 0 -and $Loop -gt 0)) { [void](Check-Once) }
        $checks++
        if ($Loop -le 0) { break }
        if ($Count -gt 0 -and $checks -ge $Count) { break }
        Start-Sleep -Seconds $Loop
    }
}

# ---- 3/3 Summary -------------------------------------------------------------------------------
Format-CcTable -File $alertsTab
$sum = @()
$sum += ('WN-44 Windows change watch  {0}' -f [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm 'UTC'"))
$sum += ('Baseline: {0}{1}   checks: {2}   state: {3}' -f [IO.File]::ReadAllText((Join-Path $BaseDir 'taken.txt')).Trim(), $(if ($newBase) { ' (new)' } else { '' }), $(if ($newBase -and $Loop -le 0) { 0 } else { $checks }), $State)
$sum += ('Alerts: {0} HIGH, {1} MED, {2} LOW' -f $tot.HIGH, $tot.MED, $tot.LOW)
$sum += ('Everything that differs from the baseline: ' + (Join-Path $State 'changes-since-baseline.txt'))
if ($tot.HIGH -gt 0) { $sum += 'HIGH: WN-42 removes persistence, WN-23 / WN-42 admins, WN-50 brings services back, WN-16 checks new pages.' }
$sum += 'Your own changes show up too: after hardening, run with -Accept.'
[IO.File]::WriteAllLines((Join-Path $Cc.RunDir 'summary.txt'), [string[]]$sum)
Write-CcHeader '3/3  summary'
foreach ($l in $sum) { $col = ''; if ($l -like 'WN-44 *') { $col = 'Cyan' } elseif ($l -like 'Alerts:*' -and $tot.HIGH -gt 0) { $col = 'Red' }; Write-CcShow -Color $col -Text $l }
Write-Host ('All results: ' + $Cc.RunDir)   # always shown, even with -Quiet
Complete-Cc
