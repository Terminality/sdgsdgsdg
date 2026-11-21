# =============================================================================
# ID:       WN-50
# NAME:     Windows service recovery (find out why a service is down, bring it back)
# ROLE:     Windows / AD  (any time a scored service goes red)
# KIND:     changes - dry run unless -Apply
# VERSION:  1.0.0
#
# PURPOSE
#   When a scored service goes down, starting it again often is not enough:
#   red team broke something under it.  This checks each service the same
#   way, finds the reason, and offers the fix.  The Windows twin of SV-50.
#
#     web       IIS (W3SVC, WAS), Apache, nginx; IIS sites and app pools
#     database  SQL Server, MySQL, MariaDB
#     domain    NTDS, DNS, Kerberos (Kdc), Netlogon, W32Time, ADWS, DFSR
#     others    RDP (TermService), file sharing (LanmanServer), WinRM, FTP,
#               the event log, and every service on the protected list
#
#   For each one that is installed:
#     1  running?        stopped, or disabled (will not start at all)
#     2  its program?    missing, or in a temp or user folder (WN-42)
#     3  port?           listening; or ANOTHER program holds the port
#     4  answers?        a connection to the port; a web page under 500
#     5  firewall?       an inbound block rule on its port
#     6  crash restart?  set to restart by itself when it crashes
#   IIS: a stopped site or app pool (a favourite: the service runs, the
#   site does not).  Once for the box: the system drive almost full.
#
#   Fixes offered (each asked, yes/no): turn off the block rule, stop the
#   program holding the port, set "starts at boot" (Automatic) when
#   disabled, start or restart, start the site or app pool, restart on
#   crash.  Each fixed service is checked again.
#
#   -Watch checks every N seconds and prints a line the moment a service
#   goes down or comes back; with -AutoRestart -Apply it also starts a
#   service that went down (at most 3 times in 10 minutes each, so a crash
#   loop is not hidden).
#
#   No revert timer: these fixes bring services UP; undoing them would take
#   them down again.  Each change still has an undo line (revert.ps1).
#
#   QUESTIONS (Enter takes the default in capitals; a parameter answers each):
#     which box                       -Box NAME (guessed)
#     which services                  -Services a,b (Enter = all found)
#     each fix (yes / no)             -Fix KINDS (always yes for these kinds)
#     apply these fixes?              -Apply (Enter = no: a dry run)
#
# USAGE
#   powershell -NoProfile -ExecutionPolicy Bypass -File WN-50-service-recovery.ps1               check, dry run
#   powershell ... WN-50-service-recovery.ps1 -Apply                                            check and fix (asks)
#   powershell ... WN-50-service-recovery.ps1 -Apply -Batch -Services W3SVC,DNS
#   powershell ... WN-50-service-recovery.ps1 -Watch 30 -AutoRestart -Apply
#   Run in an elevated window.
#
# OPTIONS
#   -Box NAME          dc | web | ecomm | fileshare | db | other (asked)
#   -Services a,b      only these services (their names, e.g. W3SVC,DNS)
#   -Fix KINDS         answer yes for these fix kinds: firewall kill enable
#                      start pool recovery (default: each asked; -Batch
#                      takes the default shown)
#   -Watch SECONDS     keep checking; print changes (Ctrl-C to stop)
#   -AutoRestart       with -Watch and -Apply: start what goes down
#   -WatchCount N      with -Watch: stop after N rounds (tests)
#   -Batch             no questions: the defaults (a dry run unless -Apply)
#   -NoColor           no colours
#   Common options (-Apply, -Out, -Protected, -NoProtected, -ForceScored,
#   -Quiet, -DebugLog) come from the library.
#
# OUTPUTS  (under -Out, one numbered folder per run: recovery-1, -2, ...)
#   output.txt   everything shown on screen, without colour
#   status.txt   each service: state, start, port, answer, problems
#   summary.txt, run.txt, undo.txt, revert.ps1;  watch.txt with -Watch
#
# DEPENDS ON
#   WMI (Win32_Service), netstat.exe, sc.exe, netsh.exe, the firewall COM
#   object (HNetCfg.FwPolicy2), appcmd.exe for IIS: Windows 7 / Server
#   2008 R2 and later.  $env:BT_WN50_FAKE names a folder of stand-in state
#   for the tests: then nothing real is read or changed.
#
# TESTED ON
#   PowerShell 7 on Linux against stand-in state (tests/wn50.Tests.ps1).
#   NOT yet run on real Windows: run it on a throwaway VM first.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - "Up" here means it answers on this box.  If scoring still fails,
#     check the firewall between (WN-25, the router) and the scoring address.
#   - A defaced site answers 200: look at the page yourself; WN-16 for shells.
#   - A firewall rule is turned off by name: rules sharing that name are
#     turned off together.
#
# DEBUGGING
#   -DebugLog shows each check.  status.txt holds every result.
# =============================================================================
param(
    [switch]$Apply, [string]$Out, [string]$Protected, [switch]$NoProtected,
    [switch]$ForceScored, [switch]$Quiet, [switch]$DebugLog,
    [string]$Box = '',
    [string[]]$Services = @(),
    [string[]]$Fix = @(),
    [int]$Watch = 0,
    [switch]$AutoRestart,
    [int]$WatchCount = 0,
    [switch]$Help,
    [switch]$Batch,
    [switch]$NoColor
)

if ($Help) {
    Write-Host 'WN-50 Windows service recovery - why a service is down, and the fix'
    Write-Host '  -Box NAME       dc web ecomm fileshare db other (asked; guessed)'
    Write-Host '  -Services a,b   only these (Enter = all found)'
    Write-Host '  -Fix KINDS      yes for these: firewall kill enable start pool recovery'
    Write-Host '  -Watch SECONDS  keep checking   -AutoRestart (with -Apply)   -WatchCount N'
    Write-Host '  -Batch -NoColor -Apply -Out DIR -Protected FILE -NoProtected -Quiet -DebugLog'
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
function Split-List($a) { return @(@($a) | Where-Object { $_ } | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
$Services = Split-List $Services
$FixKinds = @('firewall', 'kill', 'enable', 'start', 'pool', 'recovery')
$Fix = @(Split-List $Fix | ForEach-Object { $_.ToLower() })
foreach ($k in $Fix) { if (-not ($FixKinds -contains $k)) { Write-Host ("unknown fix kind '{0}' ({1})" -f $k, ($FixKinds -join ' ')); exit 2 } }
if (-not (Test-CcBox $Box)) { Write-Host ("unknown box '{0}' (dc web ecomm fileshare db other)" -f $Box); exit 2 }
if ($Watch -lt 0 -or ($Watch -gt 0 -and $Watch -lt 5)) { Write-Host '-Watch must be 5 seconds or more'; exit 2 }
if ($AutoRestart -and $Watch -eq 0) { Write-Host '-AutoRestart needs -Watch SECONDS'; exit 2 }
function Lc($s) { if ($null -eq $s) { return '' }; return ([string]$s).ToLower() }
function Q([string]$s) { return ConvertTo-CcQuoted $s }

# ---- What each service needs ----------------------------------------------------
# name (wildcards allowed) -> ports, the program that should own them, web check, box kinds where it is scored
$Known = @(
    @{ N = 'W3SVC'; Ports = @(80); Owner = 'system'; Web = $true; Box = 'web ecomm'; What = 'IIS web server' },
    @{ N = 'WAS'; Ports = @(); Owner = ''; Web = $false; Box = 'web ecomm'; What = 'IIS process activation' },
    @{ N = 'Apache*'; Ports = @(80); Owner = 'httpd.exe'; Web = $true; Box = 'web ecomm'; What = 'Apache web server' },
    @{ N = 'nginx'; Ports = @(80); Owner = 'nginx.exe'; Web = $true; Box = 'web ecomm'; What = 'nginx web server' },
    @{ N = 'MSSQLSERVER'; Ports = @(1433); Owner = 'sqlservr.exe'; Web = $false; Box = 'db ecomm web'; What = 'SQL Server' },
    @{ N = 'MSSQL$*'; Ports = @(); Owner = 'sqlservr.exe'; Web = $false; Box = 'db ecomm web'; What = 'SQL Server (named)' },
    @{ N = 'MySQL*'; Ports = @(3306); Owner = 'mysqld.exe'; Web = $false; Box = 'db ecomm web'; What = 'MySQL' },
    @{ N = 'MariaDB*'; Ports = @(3306); Owner = 'mysqld.exe'; Web = $false; Box = 'db ecomm web'; What = 'MariaDB' },
    @{ N = 'NTDS'; Ports = @(389, 3268); Owner = 'lsass.exe'; Web = $false; Box = 'dc'; What = 'Active Directory' },
    @{ N = 'Kdc'; Ports = @(88); Owner = 'lsass.exe'; Web = $false; Box = 'dc'; What = 'Kerberos' },
    @{ N = 'DNS'; Ports = @(53); Owner = 'dns.exe'; Web = $false; Box = 'dc'; What = 'DNS server' },
    @{ N = 'Netlogon'; Ports = @(); Owner = ''; Web = $false; Box = 'dc'; What = 'domain logons' },
    @{ N = 'W32Time'; Ports = @(); Owner = ''; Web = $false; Box = 'dc'; What = 'time (Kerberos needs it)' },
    @{ N = 'ADWS'; Ports = @(9389); Owner = 'microsoft.activedirectory.webservices.exe'; Web = $false; Box = 'dc'; What = 'AD web services' },
    @{ N = 'DFSR'; Ports = @(); Owner = ''; Web = $false; Box = 'dc'; What = 'SYSVOL replication' },
    @{ N = 'LanmanServer'; Ports = @(445); Owner = 'system'; Web = $false; Box = 'dc fileshare'; What = 'file sharing (SMB)' },
    @{ N = 'TermService'; Ports = @(3389); Owner = 'svchost.exe'; Web = $false; Box = 'all'; What = 'Remote Desktop' },
    @{ N = 'WinRM'; Ports = @(5985); Owner = 'system'; Web = $false; Box = ''; What = 'remote PowerShell' },
    @{ N = 'FTPSVC'; Ports = @(21); Owner = 'svchost.exe'; Web = $false; Box = ''; What = 'IIS FTP' },
    @{ N = 'EventLog'; Ports = @(); Owner = ''; Web = $false; Box = 'all'; What = 'the event log (red team stops it to hide)' }
)
function Get-Known([string]$name) { foreach ($k in $Known) { if ($name -like $k.N) { return $k } }; return $null }

# ---- Start ------------------------------------------------------------------
Initialize-Cc -Id 'WN-50' -Name 'Windows service recovery' -Kind changes -Bound $PSBoundParameters
$Fake = $env:BT_WN50_FAKE
if ($Fake) { Write-CcLog -Level WARN -Message "TEST MODE: stand-in state from $Fake; nothing real is read or changed" }
Use-CcNumberedDir 'recovery'
Write-CcShow -Color Cyan -Text ('WN-50 Windows service recovery | host {0} | results in {1}' -f $Cc.Host, $Cc.RunDir)
Write-CcLegend -Marks @('Green=[ok] up', 'Red=[!] down or broken', 'Yellow=[*] a problem', 'Yellow=[~] would fix', 'Green=[+] fixed', 'Red=[x] failed')
if ($Cc.Apply -and -not $Fake) { Assert-CcAdmin }

# ---- Reading (or the stand-in) ------------------------------------------------------
function FP([string]$n) { return (Join-Path $Fake $n) }
function F-Read([string]$n) { $p = FP $n; if (-not (Test-Path -LiteralPath $p)) { return @() }; return @(Import-Csv -LiteralPath $p) }
function R-Services {
    if ($Fake) { return @(F-Read 'services.csv' | ForEach-Object { New-Object PSObject -Property @{ Name = $_.name; Display = $_.display; State = $_.state; Mode = $_.startmode; Path = $_.path } }) }
    $s = @(Get-WmiObject -Class Win32_Service -ErrorAction SilentlyContinue)
    return @($s | ForEach-Object { New-Object PSObject -Property @{ Name = [string]$_.Name; Display = [string]$_.DisplayName; State = [string]$_.State; Mode = [string]$_.StartMode; Path = [string]$_.PathName } })
}
function R-Listeners {
    $lines = @(); $procs = @{}
    if ($Fake) {
        $p = FP 'netstat.txt'; if (Test-Path -LiteralPath $p) { $lines = @([IO.File]::ReadAllLines($p)) }
        foreach ($r in @(F-Read 'processes.csv')) { $procs[$r.pid] = $r }
    } else {
        $lines = @(Invoke-CcProgram -FilePath 'netstat.exe' -Arguments @('-ano'))
        foreach ($p in @(Get-WmiObject -Class Win32_Process -ErrorAction SilentlyContinue)) { $procs[[string]$p.ProcessId] = New-Object PSObject -Property @{ pid = [string]$p.ProcessId; name = [string]$p.Name; path = [string]$p.ExecutablePath } }
    }
    $out = @{}
    foreach ($l in $lines) {
        $f = @($l.Trim() -split '\s+')
        if ($f.Count -lt 5 -or $f[0].ToUpper() -ne 'TCP') { continue }
        $ri = $f[2].LastIndexOf(':'); if ($ri -lt 0 -or $f[2].Substring($ri + 1) -ne '0') { continue }
        $li = $f[1].LastIndexOf(':'); if ($li -lt 0) { continue }
        $port = 0; if (-not [int]::TryParse($f[1].Substring($li + 1), [ref]$port)) { continue }
        if ($out.ContainsKey($port)) { continue }
        $procId = $f[4]; $pr = $procs[$procId]; $name = ''; $path = ''
        if ($pr) { $name = [string]$pr.name; $path = [string]$pr.path }; if ($procId -eq '4') { $name = 'System' }
        $out[$port] = New-Object PSObject -Property @{ Pid = $procId; Name = $name; Path = $path }
    }
    return $out
}
# Inbound block rules: name, ports text, protocol.
function R-BlockRules {
    if ($Fake) { return @(F-Read 'fwrules.csv' | Where-Object { $_.enabled -eq 'True' -and $_.action -eq 'Block' -and $_.dir -eq 'In' } | ForEach-Object { New-Object PSObject -Property @{ Name = $_.name; Ports = $_.ports; Proto = $_.protocol } }) }
    $out = @()
    try {
        $fw = New-Object -ComObject HNetCfg.FwPolicy2
        foreach ($r in @($fw.Rules)) {
            if (-not $r.Enabled -or $r.Direction -ne 1 -or $r.Action -ne 0) { continue }
            if ($r.Protocol -ne 6 -and $r.Protocol -ne 256) { continue }
            $out += New-Object PSObject -Property @{ Name = [string]$r.Name; Ports = [string]$r.LocalPorts; Proto = $(if ($r.Protocol -eq 6) { 'TCP' } else { 'Any' }) }
        }
    } catch { Write-CcLog -Level WARN -Message ('firewall rules not read: ' + $_.Exception.Message) }
    return $out
}
function Test-PortIn([string]$spec, [int]$port) {
    if (-not $spec -or $spec -eq '*' -or (Lc $spec) -eq 'any') { return $true }
    foreach ($p in ($spec -split ',')) {
        $p = $p.Trim()
        if ($p -match '^(\d+)-(\d+)$') { if ($port -ge [int]$matches[1] -and $port -le [int]$matches[2]) { return $true } }
        elseif ($p -eq [string]$port) { return $true }
    }
    return $false
}
$AppCmd = ''; if ($env:windir) { $AppCmd = Join-Path $env:windir 'System32\inetsrv\appcmd.exe' }
function R-Iis {
    if ($Fake) { return @(F-Read 'iis.csv' | ForEach-Object { New-Object PSObject -Property @{ Kind = $_.kind; Name = $_.name; State = $_.state } }) }
    $out = @()
    if (-not $AppCmd -or -not (Test-Path -LiteralPath $AppCmd)) { return $out }
    foreach ($k in @('site', 'apppool')) {
        foreach ($l in @(Invoke-CcProgram -FilePath $AppCmd -Arguments @('list', $k))) {
            # SITE "Default Web Site" (id:1,bindings:...,state:Started)   APPPOOL "DefaultAppPool" (MgdVersion:v4.0,MgdMode:Integrated,state:Started)
            if ($l -match '^\w+\s+"([^"]+)"\s+\(.*state:(\w+)') { $out += New-Object PSObject -Property @{ Kind = $k; Name = $matches[1]; State = $matches[2] } }
        }
    }
    return $out
}
function R-Recovery([string]$name) {
    if ($Fake) { foreach ($r in @(F-Read 'services.csv')) { if ($r.name -eq $name) { return ($r.recovery -eq 'restart') } }; return $false }
    $t = (@(Invoke-CcProgram -FilePath 'sc.exe' -Arguments @('qfailure', $name)) -join ' ')
    return ($t -match 'RESTART')
}
function R-DiskFree {
    if ($Fake) { $p = FP 'disk.txt'; if (Test-Path -LiteralPath $p) { return [int]([IO.File]::ReadAllText($p).Trim()) }; return 50 }
    try {
        $d = Get-WmiObject -Class Win32_LogicalDisk -Filter ("DeviceID='" + $env:SystemDrive + "'") -ErrorAction Stop
        if ($d.Size -gt 0) { return [int](100 * $d.FreeSpace / $d.Size) }
    } catch { }
    return 100
}
# Test-Answers PORT WEB -> '' when it answers, or why not.
function Test-Answers([int]$port, [bool]$web) {
    if ($Fake) {
        $l = R-Listeners; if (-not $l.ContainsKey($port)) { return 'nothing answers' }
        if ($web) { $p = FP 'http-status.txt'; if (Test-Path -LiteralPath $p) { $c = [int]([IO.File]::ReadAllText($p).Trim()); if ($c -ge 500) { return ('the page answers ' + $c) } } }
        return ''
    }
    if ($web) {
        try {
            $req = [Net.HttpWebRequest]::Create('http://127.0.0.1:' + $port + '/'); $req.Timeout = 8000; $req.AllowAutoRedirect = $false
            $resp = $req.GetResponse(); $resp.Close(); return ''
        } catch [Net.WebException] {
            if ($_.Exception.Response) { $c = [int]$_.Exception.Response.StatusCode; if ($c -ge 500) { return ('the page answers ' + $c) }; return '' }
            return ('no answer: ' + $_.Exception.Message)
        } catch { return 'no answer' }
    }
    try {
        $tc = New-Object Net.Sockets.TcpClient; $ar = $tc.BeginConnect('127.0.0.1', $port, $null, $null)
        $ok = $ar.AsyncWaitHandle.WaitOne(3000, $false); if ($ok) { $tc.EndConnect($ar) }; $tc.Close()
        if ($ok) { return '' } else { return 'no answer in 3 seconds' }
    } catch { return 'connection refused' }
}
$OddRe = '(\\users\\public\\|\\perflogs\\|\\windows\\temp\\|\\temp\\|\\tmp\\|\\appdata\\|\\downloads\\|\$recycle\.bin)'
function Get-Exe([string]$cmd) {
    $c = $cmd.Trim(); if (-not $c) { return '' }
    if ($c.StartsWith('"')) { $e = $c.IndexOf('"', 1); if ($e -gt 0) { return $c.Substring(1, $e - 1) } }
    $m = [regex]::Match($c, '^(.+?\.exe)', 'IgnoreCase'); if ($m.Success) { return $m.Groups[1].Value }
    return ($c -split '\s+')[0]
}

# ---- 1/4 Questions and what to check -------------------------------------------------
Write-CcHeader '1/4  questions and what to check'
if (-not $Box) { $Box = Read-CcBox -Question 'Which box is this? (its scored services come first)' }
$script:all = @(R-Services); $all = $script:all
$byName = @{}; foreach ($s in $all) { $byName[(Lc $s.Name)] = $s }
$check = New-Object System.Collections.ArrayList
function Add-Check($s, [string]$why) { foreach ($c in $check) { if ($c.Svc.Name -eq $s.Name) { return } }; [void]$check.Add((New-Object PSObject -Property @{ Svc = $s; K = (Get-Known $s.Name); Why = $why; Problems = @(); Fixes = @(); Result = ''; Unused = $false; Applied = '' })) }
if ($Services.Count -gt 0) {
    foreach ($n in $Services) {
        $m = @($all | Where-Object { $_.Name -like $n })
        if ($m.Count -eq 0) { Write-CcShow -Color Yellow -Text ('  [*] {0}: no such service on this box' -f $n) }
        foreach ($s in $m) { Add-Check $s '-Services' }
    }
} else {
    $prot = @(); if ($Cc.Protected) { foreach ($s in $all) { if (Test-CcProtected -Type service -Value $s.Name) { $prot += $s } } }
    foreach ($s in $prot) { Add-Check $s 'protected list (scored)' }
    foreach ($k in $Known) { foreach ($s in @($all | Where-Object { $_.Name -like $k.N })) { if ($k.Box -eq 'all' -or ($k.Box -split ' ') -contains $Box -or $s.State -eq 'Running' -or $s.Mode -eq 'Auto') { Add-Check $s $k.What } } }
    $scored = @($check | Where-Object { $_.Why -eq 'protected list (scored)' -or ($_.K -and (($_.K.Box -split ' ') -contains $Box)) })
    if ($check.Count -gt $scored.Count -and $scored.Count -gt 0) {
        $names = ($check | ForEach-Object { $_.Svc.Name }) -join ' '
        $a = Read-CcChoice -Question ('Check which services? (found: ' + $names + ')') -Default a -Options @('a=all of them', ('s=only the scored ones for a ' + $Box + ' box (' + (($scored | ForEach-Object { $_.Svc.Name }) -join ' ') + ')'))
        if ($a -eq 's') { $keep = @($scored); $check.Clear(); foreach ($c in $keep) { [void]$check.Add($c) } }
    }
    if ($Box -eq 'dc') { foreach ($k in $Known) { if (($k.Box -split ' ') -contains 'dc' -and $k.N -notmatch '\*' -and -not $byName.ContainsKey((Lc $k.N)) -and $k.N -ne 'FTPSVC') { Write-CcShow -Color Yellow -Text ('  [*] {0} ({1}) is not installed on this domain controller' -f $k.N, $k.What) } } }
}
if ($check.Count -eq 0) { Write-CcShow -Color Yellow -Text '  [*] nothing to check: name services with -Services' }

# ---- The fixes -------------------------------------------------------------------------
# Each fix: Kind, Text, Default (y/n), Do (a command string), Undo (a command string).
function F-SetCmd([string]$file, [string]$keyCol, [string]$key, [string]$col, [string]$val) {
    return ('$f = ' + (Q (FP $file)) + '; $r = @(Import-Csv -LiteralPath $f); foreach ($x in $r) { if ($x.' + $keyCol + ' -eq ' + (Q $key) + ') { $x.' + $col + ' = ' + (Q $val) + ' } }; $r | Export-Csv -LiteralPath $f -NoTypeInformation')
}
function New-Fix($c, [string]$kind, [string]$text, [string]$def, [string]$do, [string]$undo) {
    $c.Fixes += New-Object PSObject -Property @{ Kind = $kind; Text = $text; Default = $def; Do = $do; Undo = $undo; Chosen = $false; Done = '' }
}
function Start-Cmd($s, $k) {
    if ($Fake) {
        $cmd = F-SetCmd 'services.csv' 'name' $s.Name 'state' 'Running'
        if ($k) { foreach ($p in $k.Ports) {
            $pid2 = '7' + $p; $own = $k.Owner; if ($own -eq 'system') { $pid2 = '4' }
            $cmd += ('; Add-Content -LiteralPath ' + (Q (FP 'netstat.txt')) + ' -Value ' + (Q ('  TCP    0.0.0.0:' + $p + '    0.0.0.0:0    LISTENING    ' + $pid2)))
            if ($pid2 -ne '4') { $cmd += ('; Add-Content -LiteralPath ' + (Q (FP 'processes.csv')) + ' -Value ' + (Q ($pid2 + ',' + $own + ',C:\Program Files\x\' + $own))) }
        } }
        return $cmd
    }
    return ('Start-Service -Name ' + (Q $s.Name) + ' -ErrorAction Stop')
}
function Stop-Cmd($s) { if ($Fake) { return (F-SetCmd 'services.csv' 'name' $s.Name 'state' 'Stopped') }; return ('Stop-Service -Name ' + (Q $s.Name) + ' -Force') }

# ---- 2/4 Checks --------------------------------------------------------------------------
function Check-One($c, [bool]$quiet) {
    $s = $c.Svc; $k = $c.K; $c.Problems = @(); $c.Fixes = @(); $c.Unused = $false
    $listen = R-Listeners
    $exe = Get-Exe $s.Path
    if ($exe -and -not $Fake -and -not (Test-Path -LiteralPath $exe)) { $c.Problems += ('its program is missing: ' + $exe + ' (reinstall the role or feature, or restore it from the WN-35 backup)') }
    if ($exe -and (Lc $exe) -match $OddRe) { $c.Problems += ('its program is in a temp or user folder: ' + $exe + ' - red team may have replaced it (WN-42)') }
    $running = ($s.State -eq 'Running')
    # Firewall first: a block rule on its port.
    $rules = @(R-BlockRules)
    if ($k) { foreach ($p in $k.Ports) { foreach ($r in $rules) { if (Test-PortIn $r.Ports $p) {
        $c.Problems += ('the firewall blocks port {0}: rule "{1}"' -f $p, $r.Name)
        $do = $(if ($Fake) { F-SetCmd 'fwrules.csv' 'name' $r.Name 'enabled' 'False' } else { 'netsh.exe advfirewall firewall set rule name=' + (Q $r.Name) + ' new enable=no' })
        $un = $(if ($Fake) { F-SetCmd 'fwrules.csv' 'name' $r.Name 'enabled' 'True' } else { 'netsh.exe advfirewall firewall set rule name=' + (Q $r.Name) + ' new enable=yes' })
        New-Fix $c 'firewall' ('turn off the firewall rule "' + $r.Name + '" (it blocks port ' + $p + ')') 'y' $do $un
    } } } }
    # Another program on its port.  When it is another known server that is
    # running (Apache from XAMPP on 80 while IIS is stopped), this one is not
    # in use: reported, nothing offered.
    if ($k -and $k.Owner) { foreach ($p in $k.Ports) {
        if (-not $listen.ContainsKey($p)) { continue }
        $o = $listen[$p]; $on = Lc $o.Name
        if ($on -eq $k.Owner) { continue }
        $other = ''
        foreach ($kk in $Known) { if ($kk.Owner -eq $on -and $kk.N -ne $k.N) { foreach ($s2 in $script:all) { if ($s2.Name -like $kk.N -and $s2.State -eq 'Running') { $other = $s2.Name } } } }
        if ($other -and -not $running) { $c.Problems += ('port {0} is served by {1} ({2}): {3} is not the one in use here' -f $p, $other, $o.Name, $s.Name); $c.Unused = $true; continue }
        $odd = ((Lc $o.Path) -match $OddRe)
        $c.Problems += ('another program holds port {0}: {1} (pid {2}{3})' -f $p, $o.Name, $o.Pid, $(if ($o.Path) { ', ' + $o.Path } else { '' }))
        $do = $(if ($Fake) { '$f = ' + (Q (FP 'netstat.txt')) + '; [IO.File]::WriteAllLines($f, [string[]]@([IO.File]::ReadAllLines($f) | Where-Object { ($_.Trim() -split ''\s+'')[-1] -ne ' + (Q $o.Pid) + ' }))' } else { 'Stop-Process -Id ' + $o.Pid + ' -Force -ErrorAction Stop' })
        New-Fix $c 'kill' ('stop ' + $o.Name + ' (pid ' + $o.Pid + ') so ' + $s.Name + ' gets port ' + $p) $(if ($odd -or -not $o.Name) { 'y' } else { 'n' }) $do ('Write-Host ' + (Q ('WN-50 stopped ' + $o.Name + ' (pid ' + $o.Pid + '): start it again by hand if it was needed')))
    } }
    if ($c.Unused) { $c.Result = 'not in use: ' + ($c.Problems -join '; '); return }
    if ($s.Mode -eq 'Disabled') {
        $c.Problems += 'disabled: it cannot start'
        $old = @{ Auto = 'auto'; Manual = 'demand'; Disabled = 'disabled' }[$s.Mode]
        $do = $(if ($Fake) { F-SetCmd 'services.csv' 'name' $s.Name 'startmode' 'Auto' } else { 'sc.exe config ' + (Q $s.Name) + ' start= auto' })
        $un = $(if ($Fake) { F-SetCmd 'services.csv' 'name' $s.Name 'startmode' $s.Mode } else { 'sc.exe config ' + (Q $s.Name) + ' start= ' + $old })
        New-Fix $c 'enable' ('set ' + $s.Name + ' to start at boot (Automatic)') 'y' $do $un
    }
    if (-not $running) {
        $c.Problems += ('not running (' + $s.State + ')')
        New-Fix $c 'start' ('start ' + $s.Name) 'y' (Start-Cmd $s $k) (Stop-Cmd $s)
    } else {
        $deaf = @()
        if ($k) { foreach ($p in $k.Ports) { if (-not $listen.ContainsKey($p)) { $deaf += $p } } }
        foreach ($p in $deaf) { $c.Problems += ('running, but nothing listens on port ' + $p) }
        if ($k) { foreach ($p in $k.Ports) { if ($listen.ContainsKey($p)) { $why = Test-Answers $p $k.Web; if ($why) { $c.Problems += ('port ' + $p + ': ' + $why) ; $deaf += $p } } } }
        if ($deaf.Count -gt 0 -and @($c.Fixes | Where-Object { $_.Kind -eq 'kill' -or $_.Kind -eq 'firewall' }).Count -eq 0) {
            $do = $(if ($Fake) { (Stop-Cmd $s) + '; ' + (Start-Cmd $s $k) } else { 'Restart-Service -Name ' + (Q $s.Name) + ' -Force -ErrorAction Stop' })
            New-Fix $c 'start' ('restart ' + $s.Name) 'y' $do ('Write-Host ' + (Q ('WN-50 restarted ' + $s.Name + ': nothing to undo')))
        }
    }
    # IIS: stopped sites and app pools.
    if ($s.Name -eq 'W3SVC') {
        foreach ($i in @(R-Iis)) {
            if ($i.State -eq 'Started') { continue }
            $c.Problems += ('IIS {0} "{1}" is {2}' -f $i.Kind, $i.Name, $i.State)
            $arg = $(if ($i.Kind -eq 'site') { '/site.name:' } else { '/apppool.name:' })
            $do = $(if ($Fake) { F-SetCmd 'iis.csv' 'name' $i.Name 'state' 'Started' } else { '& ' + (Q $AppCmd) + ' start ' + $i.Kind + ' ' + (Q ($arg + $i.Name)) })
            $un = $(if ($Fake) { F-SetCmd 'iis.csv' 'name' $i.Name 'state' $i.State } else { '& ' + (Q $AppCmd) + ' stop ' + $i.Kind + ' ' + (Q ($arg + $i.Name)) })
            New-Fix $c 'pool' ('start the IIS ' + $i.Kind + ' "' + $i.Name + '"') 'y' $do $un
        }
    }
    # Restart on crash: for the scored ones that are not set to.
    if ($k -and $k.N -ne 'EventLog' -and -not (R-Recovery $s.Name)) {
        $do = $(if ($Fake) { F-SetCmd 'services.csv' 'name' $s.Name 'recovery' 'restart' } else { 'sc.exe failure ' + (Q $s.Name) + ' reset= 86400 actions= restart/5000/restart/10000/restart/30000' })
        $un = $(if ($Fake) { F-SetCmd 'services.csv' 'name' $s.Name 'recovery' '' } else { 'cmd.exe /c ' + (Q ('sc.exe failure "' + $s.Name + '" reset= 0 actions= ""')) })
        New-Fix $c 'recovery' ('make ' + $s.Name + ' restart by itself when it crashes (after 5 s, 10 s, 30 s)') 'y' $do $un
    }
    $c.Result = $(if (@($c.Problems).Count -eq 0) { 'up' } else { ($c.Problems -join '; ') })
}
function Show-One($c) {
    $s = $c.Svc
    if ($c.Unused) { Write-CcShow -Color DarkGray -Text ('  [-] {0,-14} {1}, {2}: {3}' -f $s.Name, $s.State, $s.Mode, ($c.Problems -join '; ')); return }
    $ports = ''; if ($c.K -and $c.K.Ports.Count -gt 0) { $ports = ' port ' + ($c.K.Ports -join ',') }
    if (@($c.Problems).Count -eq 0) { Write-CcShow -Color Green -Text ('  [ok] {0,-14} running{1} ({2})' -f $s.Name, $ports, $c.Why); return }
    $down = ($s.State -ne 'Running' -or @($c.Problems | Where-Object { $_ -like 'running, but*' -or $_ -like 'port *' }).Count -gt 0)
    Write-CcShow -Color $(if ($down) { 'Red' } else { 'Yellow' }) -Text ('  {0} {1,-14} {2}, {3}{4} ({5})' -f $(if ($down) { '[!]' } else { '[*]' }), $s.Name, $s.State, $s.Mode, $ports, $c.Why)
    foreach ($p in $c.Problems) { Write-CcShow -Color DarkGray -Text ('        - ' + $p) }
}

# ---- Watch mode -------------------------------------------------------------------------
if ($Watch -gt 0) {
    Write-CcHeader ('2/2  watching every {0} s (Ctrl-C to stop)' -f $Watch)
    $wf = Join-Path $Cc.RunDir 'watch.txt'
    $last = @{}; $tries = @{}; $gaveUp = @{}; $round = 0
    while ($true) {
        $round++
        $now = @(R-Services); $map = @{}; foreach ($s in $now) { $map[(Lc $s.Name)] = $s }
        $listen = R-Listeners
        foreach ($c in $check) {
            $s = $map[(Lc $c.Svc.Name)]; if (-not $s) { continue }
            $st = 'up'; $why = ''
            if ($s.State -ne 'Running') { $st = 'down'; $why = $s.State }
            elseif ($c.K) { foreach ($p in $c.K.Ports) { if (-not $listen.ContainsKey($p)) { $st = 'down'; $why = 'nothing on port ' + $p } } }
            $key = Lc $s.Name
            if (-not $last.ContainsKey($key) -or $last[$key] -ne $st) {
                $line = ('{0}  {1,-14} {2}{3}' -f [DateTime]::Now.ToString('HH:mm:ss'), $s.Name, $(if ($st -eq 'up') { 'UP' } else { 'DOWN' }), $(if ($why) { ' (' + $why + ')' } else { '' }))
                if ($last.ContainsKey($key) -or $st -eq 'down') { Write-CcShow -Color $(if ($st -eq 'up') { 'Green' } else { 'Red' }) -Text ('  ' + $line); [IO.File]::AppendAllText($wf, $line + "`r`n") }
                $last[$key] = $st
            }
            if ($st -eq 'down' -and $s.State -ne 'Running' -and $AutoRestart -and $Cc.Apply -and $s.Mode -ne 'Disabled') {
                $t = @(); if ($tries.ContainsKey($key)) { $t = @($tries[$key] | Where-Object { $_ -gt [DateTime]::Now.AddMinutes(-10) }) }
                if ($t.Count -ge 3) { if (-not $gaveUp.ContainsKey($key)) { Write-CcShow -Color Red -Text ('  [!] {0} went down 3 times in 10 minutes: not starting it again - find out why (WN-50 without -Watch)' -f $s.Name); $gaveUp[$key] = 1 }; continue }
                $cmd = Start-Cmd $s $c.K; if (-not (Test-Path -LiteralPath (Join-Path $Cc.RunDir 'revert.ps1'))) { [void](Write-CcRevert) }
                if (Invoke-CcChange -Description ('start ' + $s.Name + ' (it went down)') -Action { & ([scriptblock]::Create($cmd)) } -Undo (Stop-Cmd $s)) { Write-CcShow -Color Green -Text ('  [+] started ' + $s.Name) }
                else { Write-CcShow -Color Red -Text ('  [x] could not start ' + $s.Name) }
                $tries[$key] = @($t + [DateTime]::Now)
            } elseif ($st -eq 'down' -and $s.Mode -eq 'Disabled' -and $AutoRestart) { Write-CcShow -Color Yellow -Text ('  [*] {0} is disabled: not started (run WN-50 to fix it)' -f $s.Name) }
        }
        if ($round -eq 1) { Write-CcShow -Color DarkGray -Text ('  watching {0} service(s): {1}' -f $check.Count, (($check | ForEach-Object { $_.Svc.Name }) -join ' ')) }
        if ($WatchCount -gt 0 -and $round -ge $WatchCount) { break }
        Start-Sleep -Seconds $Watch
    }
    Write-Host ('All results: ' + $Cc.RunDir)
    Complete-Cc
}

Write-CcHeader '2/4  checks'
foreach ($c in $check) { Check-One $c $false; Show-One $c }
$free = R-DiskFree
if ($free -lt 10) { Write-CcShow -Color Red -Text ('  [!] the system drive has {0}% free: services fail to write logs and temp files - free some space' -f $free) }
$down = @($check | Where-Object { $_.Result -ne 'up' -and -not $_.Unused })
if ($check.Count -gt 0 -and $down.Count -eq 0) { Write-CcShow -Color Green -Text '  [ok] every service checked is up' }

# ---- 3/4 Fixes -------------------------------------------------------------------------------
Write-CcHeader '3/4  fixes (Enter = the default in capitals)'
$order = @{ firewall = 1; kill = 2; enable = 3; start = 4; pool = 5; recovery = 6 }
$fixes = @(); foreach ($c in $check) { foreach ($f in @($c.Fixes | Sort-Object @{ Expression = { $order[$_.Kind] } })) { $fixes += New-Object PSObject -Property @{ C = $c; F = $f } } }
if ($fixes.Count -eq 0) { Write-CcShow -Color Green -Text $(if ($down.Count -gt 0) { '  [ok] nothing to fix here (the problems above need a hand: see each one)' } else { '  [ok] nothing to fix' }) }
# Restart-on-crash for many services: one question for all of them.
$rec = @($fixes | Where-Object { $_.F.Kind -eq 'recovery' })
$recAll = ''
if ($rec.Count -gt 2 -and -not ($Fix -contains 'recovery')) {
    $recAll = $(if (Read-CcAsk -Question ('{0} services do not restart by themselves when they crash ({1}). Set all of them to?' -f $rec.Count, (($rec | ForEach-Object { $_.C.Svc.Name }) -join ' ')) -Default Y -Yes 'yes, restart after 5 s, 10 s, 30 s' -No 'no, leave them as they are') { 'y' } else { 'n' })
}
foreach ($x in $fixes) {
    $f = $x.F
    if ($Fix -contains $f.Kind) { $f.Chosen = $true; continue }
    if ($f.Kind -eq 'recovery' -and $recAll) { $f.Chosen = ($recAll -eq 'y'); continue }
    $f.Chosen = Read-CcAsk -Question ('[{0}] {1}?' -f $f.Kind, $f.Text) -Default $f.Default.ToUpper() -Yes 'yes, do it' -No 'no, leave it'
}
$todo = @($fixes | Where-Object { $_.F.Chosen })
if ($todo.Count -gt 0 -and -not $Cc.Apply -and (Test-CcCanAsk)) {
    if (Read-CcAsk -Question ('Make these {0} fix(es) now?' -f $todo.Count) -Default N -Yes 'yes, fix them now' -No 'no, change nothing (dry run)') {
        $Cc.Apply = $true; if (-not $Fake) { Assert-CcAdmin }
    }
}

# ---- 4/4 Apply and check again ---------------------------------------------------------------
Write-CcHeader $(if ($Cc.Apply) { '4/4  fixing, then checking again' } else { '4/4  dry run: nothing is changed' })
$ok = 0; $bad = 0
if ($todo.Count -eq 0) { if ($fixes.Count -gt 0) { Write-CcShow -Color DarkGray -Text '  No fix chosen.' } }
elseif (-not $Cc.Apply) {
    foreach ($x in $todo) { Write-CcShow -Color Yellow -Text ('  [~] ' + $x.F.Text); $Cc.Would++; $x.F.Done = 'would' }
    Write-CcShow -Color DarkGray -Text '  Dry run: nothing was changed. Run again with -Apply.'
} else {
    [void](Write-CcRevert)
    foreach ($x in $todo) {
        $f = $x.F; $cmd = $f.Do
        if (Invoke-CcChange -Description $f.Text -Action { & ([scriptblock]::Create($cmd)) } -Undo $f.Undo) { $ok++; $f.Done = 'done'; Write-CcShow -Color Green -Text ('  [+] ' + $f.Text) }
        else { $bad++; $f.Done = 'FAILED'; Write-CcShow -Color Red -Text ('  [x] FAILED: ' + $f.Text + ' (see the log)') }
    }
    Write-CcShow -Text ''
    Write-CcShow -Text '  Checked again:'
    $fresh = @(R-Services); $fm = @{}; foreach ($s in $fresh) { $fm[(Lc $s.Name)] = $s }
    foreach ($c in $check) { $c.Applied = (($c.Fixes | Where-Object { $_.Chosen } | ForEach-Object { $_.Kind + ':' + $_.Done }) -join ' ') }
    $seenC = @{}
    foreach ($x in $todo) {
        $c = $x.C; if ($seenC.ContainsKey($c.Svc.Name)) { continue }; $seenC[$c.Svc.Name] = 1
        if ($fm.ContainsKey((Lc $c.Svc.Name))) { $c.Svc = $fm[(Lc $c.Svc.Name)] }
        Check-One $c $true
        $left = @($c.Problems | Where-Object { $_ -notlike '*restart by itself*' })
        if ($left.Count -eq 0) { $c.Result = 'up'; Write-CcShow -Color Green -Text ('  [ok] {0} is up' -f $c.Svc.Name) } else { Show-One $c }
    }
}

# ---- Summary ----------------------------------------------------------------------------------
$tab = New-CcTable -Name status -Columns @('service', 'what', 'state', 'start', 'ports', 'result', 'fixes')
foreach ($c in $check) { Add-CcTableRow -File $tab -Values @($c.Svc.Name, $c.Why, $c.Svc.State, $c.Svc.Mode, $(if ($c.K) { ($c.K.Ports -join ',') } else { '' }), $c.Result, $(if ($c.Applied) { $c.Applied } else { (($c.Fixes | Where-Object { $_.Chosen } | ForEach-Object { $_.Kind + ':' + $(if ($_.Done) { $_.Done } else { 'chosen' }) }) -join ' ') })) }
Format-CcTable -File $tab
$sum = @()
$sum += ('WN-50 Windows service recovery  {0}  {1}' -f [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm 'UTC'"), $(if ($Cc.Apply) { 'APPLIED' } else { 'DRY RUN' }))
$sum += ('Box: {0}   services checked: {1}   up: {2}   with a problem: {3}' -f $Box, $check.Count, @($check | Where-Object { $_.Result -eq 'up' }).Count, @($check | Where-Object { $_.Result -ne 'up' -and -not $_.Unused }).Count)
foreach ($c in @($check | Where-Object { $_.Result -ne 'up' -and -not $_.Unused })) { $sum += ('  DOWN {0}: {1}' -f $c.Svc.Name, $c.Result) }
if ($Cc.Apply -and $todo.Count -gt 0) { $sum += ('Fixes: {0} done, {1} failed' -f $ok, $bad) }
$sum += ''
$sum += 'Still red in scoring but up here? The firewall (WN-25 -Undo latest), the router, then the scoring address.'
[IO.File]::WriteAllLines((Join-Path $Cc.RunDir 'summary.txt'), [string[]]$sum)
Write-CcHeader 'summary'
foreach ($l in $sum) {
    $col = ''
    if ($l -like 'WN-50 *') { $col = 'Cyan' } elseif ($l -like '  DOWN*' -or ($l -like 'Fixes:*' -and $bad -gt 0)) { $col = 'Red' }
    Write-CcShow -Color $col -Text $l
}
Write-Host ('All results: ' + $Cc.RunDir)   # always shown, even with -Quiet
if ($bad -gt 0) { Complete-Cc -ExitCode 5 }
Complete-Cc
