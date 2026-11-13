# =============================================================================
# ID:       WN-25
# NAME:     Windows firewall
# ROLE:     Windows / AD  (wave 2, first 15 minutes)
# KIND:     changes - dry run unless -Apply; rolls itself back unless confirmed
# VERSION:  1.0.0
#
# PURPOSE
#   Turns the Windows firewall on for every profile with inbound blocked by
#   default, and allows in only:
#     - the ports on the protected list and -Allow (always: scored services)
#     - the ports that are listening now, minus loopback-only ones, known
#       backdoor ports, ports above 49151, -Exclude, and ports whose program
#       is a shell, netcat or something in a temp folder
#     - everything from the scoring engine and admin addresses (protected
#       list "host" entries and -AdminFrom)
#     - ping (ICMP echo), unless -NoPing
#     - on a domain controller, the ports Active Directory needs (DNS,
#       Kerberos, LDAP, GC, SMB, RPC, NTP, password change)
#   Existing rules that undo all of this - an enabled inbound rule that allows
#   everything, a rule for a shell or a program in a temp folder, a rule
#   opening a backdoor port - are turned off.  -Strict turns off EVERY
#   inbound allow rule that is not one of ours (except Active Directory's on
#   a DC).  Dropped connections are logged to Windows' firewall log.
#
#   SAFETY: the whole firewall is exported first.  A rollback task (SYSTEM,
#   runs even if this window or RDP session is gone) restores that export
#   after -ConfirmMinutes (default 5) unless someone confirms from a NEW
#   connection with keep-firewall.ps1 - proof the change did not lock the team
#   out.  -Undo puts the old firewall back at any time.
#
# USAGE
#   powershell -NoProfile -ExecutionPolicy Bypass -File WN-25-firewall.ps1 -Out C:\ccdc-out                    dry run: shows the plan
#   powershell ... WN-25-firewall.ps1 -Out C:\ccdc-out -Apply -AdminFrom 10.0.0.5
#     then, from a NEW RDP/remote session within 5 minutes:
#   powershell ... <run folder>\keep-firewall.ps1
#   powershell ... WN-25-firewall.ps1 -Out C:\ccdc-out -Undo latest -Apply     put the old firewall back
#   Run in an elevated Windows PowerShell (powershell.exe) window.
#
# OPTIONS
#   -Allow a,b         always allow these ports: 80/tcp, 53/udp, 5000-5100/tcp
#                      (no /proto means tcp)
#   -Exclude a,b       never open these ports, even if something listens on
#                      them (the protected list still wins, with a warning)
#   -AdminFrom a,b     allow everything from these addresses or networks
#                      (10.0.0.5, 10.0.0.0/24) as well as protected hosts
#   -Strict            turn off every inbound allow rule that is not ours
#   -NoPing            do not allow ICMP echo
#   -NoLog             do not turn on the dropped-connection log
#   -ConfirmMinutes N  rollback timer (default 5, 2..60)
#   -NoTimer           no rollback timer (only when you are at the console)
#   -Undo RUN          put back the firewall from before a run: "latest" or
#                      a run folder.  Dry run unless -Apply
#   -Remove            remove only the rules this script added (group "CCDC")
#   Common options (-Apply, -Out, -Protected, -NoProtected, -Quiet,
#   -DebugLog) come from the library.
#
# OUTPUTS  (under -Out, in WN-25_<host>_<UTC time>\)
#   plan.csv              every allow rule it adds and why
#   disabled.csv          every existing rule it turns off and why
#   not-allowed.csv       listening ports it did NOT open and why
#   firewall-before.wfw   the whole firewall before the change (netsh export)
#   keep-firewall.ps1     run it from a NEW connection to keep the change
#   rollback.ps1          what the timer runs; you can run it too
#   summary.txt           the plan and the result
#   Dropped connections: %windir%\System32\LogFiles\Firewall\pfirewall.log
#
# WHAT IT CHANGES  (only with -Apply)
#   Firewall profiles (on, block inbound, allow outbound, logging), adds
#   rules in the group "CCDC", turns off the existing rules listed in
#   disabled.csv, and creates the scheduled task "CCDC-WN25-rollback" until
#   the change is kept or rolled back.  Outbound traffic is not limited.
#
# DEPENDS ON
#   The firewall COM object (HNetCfg.FwPolicy2), netsh advfirewall, netstat,
#   WMI (Win32_Process), schtasks - Windows 7 / Server 2008 R2 and later.
#   $env:CCDC_WN25_FAKE names a folder of stand-in state for the tests: then
#   nothing on the machine is read or changed.
#
# TESTED ON
#   PowerShell 7 on Linux against stand-in state (tests/wn25.Tests.ps1).
#   NOT yet run on real Windows: run it on a throwaway VM first.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - A scored service that is DOWN when this runs, and is not on the
#     protected list or -Allow, is not opened.  Fill in the protected list.
#   - Group Policy firewall rules and settings win over local ones; a domain
#     GPO can put things back at the next refresh.
#   - Only inbound is limited.  IPv6 is treated like IPv4 (the same rules).
#   - netstat and WMI see what Windows reports; a rootkit can hide a listener.
#
# DEBUGGING
#   -DebugLog          every listener and rule and the decision about it
#   plan.csv / disabled.csv / not-allowed.csv   the reasons, one per line
#   schtasks /query /tn CCDC-WN25-rollback      is a rollback still waiting?
# =============================================================================
param(
    [switch]$Apply, [string]$Out, [string]$Protected, [switch]$NoProtected,
    [switch]$ForceScored, [switch]$Quiet, [switch]$DebugLog,
    [string[]]$Allow = @(),
    [string[]]$Exclude = @(),
    [string[]]$AdminFrom = @(),
    [switch]$Strict,
    [switch]$NoPing,
    [switch]$NoLog,
    [int]$ConfirmMinutes = 5,
    [switch]$NoTimer,
    [string]$Undo = '',
    [switch]$Remove,
    [switch]$Help
)

if ($Help) {
    Write-Host 'WN-25 Windows firewall - default-deny inbound, scored ports open, rollback timer'
    Write-Host '  -Allow 80/tcp,53/udp   -Exclude 8080/tcp   -AdminFrom 10.0.0.5,10.0.0.0/24'
    Write-Host '  -Strict  -NoPing  -NoLog  -ConfirmMinutes N  -NoTimer'
    Write-Host '  -Undo latest|RUNFOLDER   -Remove (only the rules this script added)'
    Write-Host '  -Apply -Out DIR -Protected FILE -NoProtected -Quiet -DebugLog'
    exit 0
}

# >>> CCDC-LIB
# Development copy: find lib/lib.ps1 by walking up from this file.  The build
# step (tools/build.sh, LB-03) replaces this whole block with the library
# itself, so the built script is a single standalone file.
$ccDir = Split-Path -Parent $MyInvocation.MyCommand.Path
while ($ccDir -and -not (Test-Path -LiteralPath (Join-Path (Join-Path $ccDir 'lib') 'lib.ps1'))) { $ccDir = Split-Path -Parent $ccDir }
if (-not $ccDir) { Write-Host 'cannot find lib/lib.ps1 above this script'; exit 3 }
. (Join-Path (Join-Path $ccDir 'lib') 'lib.ps1')
# <<< CCDC-LIB

function Lc($s) { if ($null -eq $s) { return '' }; return ([string]$s).ToLower() }
function Nz($s) { if ($null -eq $s) { return '' }; return [string]$s }
function Q([string]$s) { return "'" + $s.Replace("'", "''") + "'" }

# ---- Options ----------------------------------------------------------------
# Lists split inline (not by a function): Windows PowerShell 5.1 turns an
# empty list returned from a function into $null.
$Allow = @(@($Allow) | Where-Object { $_ } | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$Exclude = @(@($Exclude) | Where-Object { $_ } | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$AdminFrom = @(@($AdminFrom) | Where-Object { $_ } | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

# Parse-Port "80/tcp" -> @{ Proto = 'TCP'; Ports = '80' } or $null.
function Parse-Port([string]$s) {
    $m = [regex]::Match($s.Trim(), '^(\d{1,5})(-(\d{1,5}))?(/(tcp|udp))?$', 'IgnoreCase')
    if (-not $m.Success) { return $null }
    $a = [int]$m.Groups[1].Value; $b = $a
    if ($m.Groups[3].Success) { $b = [int]$m.Groups[3].Value }
    if ($a -lt 1 -or $b -gt 65535 -or $b -lt $a) { return $null }
    $proto = 'TCP'; if ($m.Groups[5].Success) { $proto = $m.Groups[5].Value.ToUpper() }
    $ports = [string]$a; if ($b -ne $a) { $ports = "$a-$b" }
    return @{ Proto = $proto; Ports = $ports; Lo = $a; Hi = $b }
}
foreach ($p in @($Allow + $Exclude)) { if ($null -eq (Parse-Port $p)) { Write-Host "not a port: '$p' (use 80, 80/tcp, 53/udp or 5000-5100/tcp)"; exit 2 } }
function Valid-Addr([string]$a) {
    if ($a -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(/(\d{1,2}))?$') {
        for ($i = 1; $i -le 4; $i++) { if ([int]$matches[$i] -gt 255) { return $false } }
        if ($matches[6] -and [int]$matches[6] -gt 32) { return $false }
        return $true
    }
    return ($a -match '^[0-9a-fA-F:]+(/\d{1,3})?$' -and $a.Contains(':'))
}
foreach ($a in $AdminFrom) { if (-not (Valid-Addr $a)) { Write-Host "-AdminFrom: not an address or network: '$a'"; exit 2 } }
if ($ConfirmMinutes -lt 2 -or $ConfirmMinutes -gt 60) { Write-Host '-ConfirmMinutes must be 2..60'; exit 2 }
if ($Undo -and $Remove) { Write-Host 'use -Undo or -Remove, not both'; exit 2 }

# ---- Start ------------------------------------------------------------------
Initialize-Cc -Id 'WN-25' -Name 'Windows firewall' -Kind changes -Bound $PSBoundParameters
$Fake = $env:CCDC_WN25_FAKE
if ($Fake) { Write-CcLog -Level WARN -Message "TEST MODE: stand-in state from $Fake; nothing on this machine is read or changed" }
else {
    if (-not (Test-CcCommand 'Get-WmiObject')) { Stop-Cc -Code 3 -Message 'run this with Windows PowerShell (powershell.exe), not PowerShell 7 (pwsh)' }
    if ($Cc.Apply) { Assert-CcAdmin }
}
$TaskName = 'CCDC-WN25-rollback'
$Group = 'CCDC'

# =============================================================================
# State providers: every read and write of the firewall goes through these,
# so the tests can use stand-in state ($env:CCDC_WN25_FAKE).
# =============================================================================
function FP([string]$n) { return [IO.Path]::Combine($Fake, $n) }
function F-Read([string]$n) { $p = FP $n; if (-not (Test-Path -LiteralPath $p)) { return @() }; return @([IO.File]::ReadAllLines($p) | ConvertFrom-Csv) }
function F-Write([string]$n, [string[]]$h, $rows) {
    $l = @(($h | ForEach-Object { '"' + $_ + '"' }) -join ',')
    foreach ($r in @($rows)) { $l += (($h | ForEach-Object { '"' + (Nz $r.$_).Replace('"', '""') + '"' }) -join ',') }
    [IO.File]::WriteAllLines((FP $n), [string[]]$l)
}
$RuleCols = @('name', 'enabled', 'protocol', 'lports', 'raddr', 'app', 'svc', 'group', 'pkg', 'laddr', 'iface', 'icmp')
$script:Fw = $null
function Fw { if ($null -eq $script:Fw) { $script:Fw = New-Object -ComObject HNetCfg.FwPolicy2 }; return $script:Fw }

# Get-Profiles -> rows: Name, On (bool), BlockIn (bool)
function Get-Profiles {
    if ($Fake) { return @(F-Read 'profiles.csv' | ForEach-Object { New-Object PSObject -Property @{ Name = $_.name; On = ($_.on -eq 'True'); BlockIn = ($_.blockin -eq 'True') } }) }
    $out = @()
    foreach ($p in @(@('Domain', 1), @('Private', 2), @('Public', 4))) {
        $out += New-Object PSObject -Property @{ Name = $p[0]; On = [bool](Fw).FirewallEnabled($p[1]); BlockIn = ((Fw).DefaultInboundAction($p[1]) -eq 0) }
    }
    return $out
}
function Set-Profiles {
    if ($Fake) { F-Write 'profiles.csv' @('name', 'on', 'blockin') @(@('Domain', 'Private', 'Public') | ForEach-Object { New-Object PSObject -Property @{ name = $_; on = 'True'; blockin = 'True' } }); return }
    foreach ($a in @(@('allprofiles', 'state', 'on'), @('allprofiles', 'firewallpolicy', 'blockinbound,allowoutbound'))) {
        [void](Invoke-CcProgram -FilePath 'netsh.exe' -Arguments (@('advfirewall', 'set') + $a))
        if ($LASTEXITCODE -ne 0) { throw ('netsh advfirewall set ' + ($a -join ' ') + " failed (exit $LASTEXITCODE)") }
    }
}
function Set-Logging {
    if ($Fake) { [IO.File]::WriteAllText((FP 'logging.txt'), 'droppedconnections enable'); return }
    foreach ($a in @(@('logging', 'droppedconnections', 'enable'), @('logging', 'maxfilesize', '32767'))) {
        [void](Invoke-CcProgram -FilePath 'netsh.exe' -Arguments (@('advfirewall', 'set', 'allprofiles') + $a))
        if ($LASTEXITCODE -ne 0) { throw "netsh logging failed (exit $LASTEXITCODE)" }
    }
}
# Get-InRules -> enabled-or-not inbound ALLOW rules as rows with $RuleCols.
function Get-InRules {
    if ($Fake) { return @(F-Read 'rules.csv') }
    $out = @()
    foreach ($r in @((Fw).Rules)) {
        if ($r.Direction -ne 1 -or $r.Action -ne 1) { continue }
        $pkg = ''; try { $pkg = [string]$r.LocalAppPackageId } catch { }
        $icmp = ''; try { $icmp = [string]$r.IcmpTypesAndCodes } catch { }
        $out += New-Object PSObject -Property @{ name = [string]$r.Name; enabled = [string][bool]$r.Enabled; protocol = [string]$r.Protocol; lports = [string]$r.LocalPorts
            raddr = [string]$r.RemoteAddresses; app = [string]$r.ApplicationName; svc = [string]$r.ServiceName; group = [string]$r.Grouping; pkg = $pkg
            laddr = [string]$r.LocalAddresses; iface = [string]$r.InterfaceTypes; icmp = $icmp }
    }
    return $out
}
# Key of a rule: what makes it this rule (names repeat).
function RKey($r) { return ((@($r.name, $r.protocol, $r.lports, $r.raddr, $r.app, $r.svc, $r.group) | ForEach-Object { Lc $_ }) -join '|') }
function Disable-Rule($x) {
    if ($Fake) {
        $rows = @(F-Read 'rules.csv'); foreach ($r in $rows) { if ((RKey $r) -eq (RKey $x)) { $r.enabled = 'False' } }
        F-Write 'rules.csv' $RuleCols $rows; return
    }
    $n = 0
    foreach ($r in @((Fw).Rules)) {
        if ($r.Direction -ne 1 -or $r.Action -ne 1) { continue }
        $k = ((@($r.Name, $r.Protocol, $r.LocalPorts, $r.RemoteAddresses, $r.ApplicationName, $r.ServiceName, $r.Grouping) | ForEach-Object { Lc $_ }) -join '|')
        if ($k -eq (RKey $x)) { $r.Enabled = $false; $n++ }
    }
    if ($n -eq 0) { throw 'rule not found any more' }
}
# Norm-Addrs "10.0.0.5,10.0.0.0/24" -> "10.0.0.0/255.255.255.0,10.0.0.5/255.255.255.255"
#   The firewall reports addresses with dotted masks; ours are compared in
#   the same form, sorted.  '' and '*' mean any.
function Norm-Addrs([string]$list) {
    if ($list -eq '' -or $list -eq '*') { return '*' }
    $o = @()
    foreach ($x in @($list -split ',')) {
        $x = $x.Trim()
        if ($x -match '^(\d+\.\d+\.\d+\.\d+)(/(\d+))?$') {
            $bits = 32; if ($matches[3]) { $bits = [int]$matches[3] }
            if ($x -match '/\d+\.') { $o += $x; continue }
            $m = @(); for ($i = 0; $i -lt 4; $i++) { $n = [Math]::Min(8, [Math]::Max(0, $bits - 8 * $i)); $m += (256 - [Math]::Pow(2, 8 - $n)) }
            $o += ($matches[1] + '/' + ($m -join '.'))
        } else { $o += $x.ToLower() }
    }
    return ((@($o) | Sort-Object) -join ',')
}
# Has-Rule NAME -> $true when a rule of ours with this name exists (a second
# run must not add every rule again).
function Has-Rule([string]$name) {
    if ($Fake) { return (@(F-Read 'rules.csv' | Where-Object { $_.group -eq $Group -and $_.name -eq $name }).Count -gt 0) }
    return (@(@((Fw).Rules) | Where-Object { $_.Grouping -eq $Group -and $_.Name -eq $name }).Count -gt 0)
}
# Add-Rule NAME PROTO PORTS RADDR -> PROTO TCP|UDP|ANY|ICMP
function Add-Rule([string]$name, [string]$proto, [string]$ports, [string]$raddr) {
    if ($Fake) {
        $rows = @(F-Read 'rules.csv')
        $rows += New-Object PSObject -Property @{ name = $name; enabled = 'True'; protocol = $proto; lports = $ports; raddr = $raddr; app = ''; svc = ''; group = $Group; pkg = ''; laddr = ''; iface = ''; icmp = '' }
        F-Write 'rules.csv' $RuleCols $rows; return
    }
    $r = New-Object -ComObject HNetCfg.FWRule
    $r.Name = $name
    $r.Description = 'Added by WN-25 (CCDC kit). Remove with WN-25 -Remove.'
    $r.Grouping = $Group
    $r.Direction = 1; $r.Action = 1; $r.Profiles = 2147483647
    switch ($proto) {
        'TCP' { $r.Protocol = 6; $r.LocalPorts = $ports }
        'UDP' { $r.Protocol = 17; $r.LocalPorts = $ports }
        'ICMP' { $r.Protocol = 1; $r.IcmpTypesAndCodes = '8:*' }
        default { $r.Protocol = 256 }
    }
    if ($raddr) { $r.RemoteAddresses = $raddr }
    $r.Enabled = $true
    (Fw).Rules.Add($r)
}
function Remove-Ours {
    if ($Fake) { $all = @(F-Read 'rules.csv'); $keep = @($all | Where-Object { $_.group -ne $Group }); F-Write 'rules.csv' $RuleCols $keep; return ($all.Count - $keep.Count) }
    $n = 0
    $names = @(@((Fw).Rules) | Where-Object { $_.Grouping -eq $Group } | ForEach-Object { $_.Name } | Select-Object -Unique)
    foreach ($nm in $names) { while (@(@((Fw).Rules) | Where-Object { $_.Grouping -eq $Group -and $_.Name -eq $nm }).Count -gt 0) { (Fw).Rules.Remove($nm); $n++ } }
    return $n
}
function Export-Fw([string]$file) {
    if ($Fake) {
        if ($env:CCDC_WN25_FAIL -eq 'export') { throw 'access denied (test)' }
        $d = $file + '.d'; New-Item -ItemType Directory -Path $d -Force | Out-Null
        foreach ($n in @('profiles.csv', 'rules.csv', 'logging.txt')) { if (Test-Path -LiteralPath (FP $n)) { Copy-Item -LiteralPath (FP $n) -Destination (Join-Path $d $n) -Force } }
        [IO.File]::WriteAllText($file, 'fake export'); return
    }
    [void](Invoke-CcProgram -FilePath 'netsh.exe' -Arguments @('advfirewall', 'export', $file))
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $file)) { throw "netsh advfirewall export failed (exit $LASTEXITCODE)" }
}
function Import-Fw([string]$file) {
    if ($Fake) {
        $d = $file + '.d'
        if (-not (Test-Path -LiteralPath (Join-Path $d 'logging.txt'))) { Remove-Item -LiteralPath (FP 'logging.txt') -Force -ErrorAction SilentlyContinue }
        foreach ($f in @(Get-ChildItem -LiteralPath $d)) { Copy-Item -LiteralPath $f.FullName -Destination (FP $f.Name) -Force }
        return
    }
    [void](Invoke-CcProgram -FilePath 'netsh.exe' -Arguments @('advfirewall', 'import', $file))
    if ($LASTEXITCODE -ne 0) { throw "netsh advfirewall import failed (exit $LASTEXITCODE)" }
}
# Listeners: netstat -ano parsed, with each process's name and program.
function Get-Listeners {
    $lines = @(); $procs = @{}
    if ($Fake) {
        $p = FP 'netstat.txt'; if (Test-Path -LiteralPath $p) { $lines = @([IO.File]::ReadAllLines($p)) }
        foreach ($r in @(F-Read 'processes.csv')) { $procs[$r.pid] = $r }
    } else {
        $lines = @(Invoke-CcProgram -FilePath 'netstat.exe' -Arguments @('-ano'))
        foreach ($p in @(Get-WmiObject -Class Win32_Process -ErrorAction SilentlyContinue)) { $procs[[string]$p.ProcessId] = New-Object PSObject -Property @{ pid = [string]$p.ProcessId; name = [string]$p.Name; path = [string]$p.ExecutablePath } }
    }
    $out = @(); $seen = @{}
    foreach ($l in $lines) {
        $f = @($l.Trim() -split '\s+')
        if ($f.Count -lt 4) { continue }
        $proto = $f[0].ToUpper()
        if ($proto -eq 'TCP' -and $f.Count -ge 5) { $procId = $f[4]; $raddr = $f[2] }
        elseif ($proto -eq 'UDP') { $procId = $f[$f.Count - 1]; $raddr = '*:*' }
        else { continue }
        $ri = $raddr.LastIndexOf(':'); if ($proto -eq 'TCP' -and $raddr.Substring($ri + 1) -ne '0') { continue }
        $li = $f[1].LastIndexOf(':'); if ($li -lt 0) { continue }
        $addr = $f[1].Substring(0, $li).Trim('[', ']'); $port = $f[1].Substring($li + 1)
        $k = "$proto|$port|$addr"
        if ($seen.ContainsKey($k)) { continue }; $seen[$k] = 1
        $pr = $procs[$procId]
        $name = ''; $path = ''; if ($pr) { $name = $pr.name; $path = $pr.path }; if ($procId -eq '4') { $name = 'System' }
        $out += New-Object PSObject -Property @{ Proto = $proto; Addr = $addr; Port = [int]$port; Pid = $procId; Name = $name; Path = $path }
    }
    return $out
}
# Rollback task: runs as SYSTEM at a fixed time, so it fires even if this
# session is gone.  The trigger time is ISO 8601 in XML, so it does not
# depend on the machine's date format.
function Task-Exists {
    if ($Fake) { return (Test-Path -LiteralPath (FP 'task.txt')) }
    [void](Invoke-CcProgram -FilePath 'schtasks.exe' -Arguments @('/query', '/tn', $TaskName))
    $e = $LASTEXITCODE; $global:LASTEXITCODE = 0
    return ($e -eq 0)
}
function Task-Delete {
    if ($Fake) { Remove-Item -LiteralPath (FP 'task.txt') -Force -ErrorAction SilentlyContinue; return }
    [void](Invoke-CcProgram -FilePath 'schtasks.exe' -Arguments @('/delete', '/tn', $TaskName, '/f'))
    $global:LASTEXITCODE = 0
}
# Pending-Run -> the run folder whose change is neither kept nor rolled back
# (has rollback.ps1, no KEPT, no ROLLED_BACK), or ''.
function Pending-Run {
    foreach ($d in @(Get-ChildItem -LiteralPath $Cc.Out -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer -and $_.Name -like ('WN-25_' + $Cc.Host + '_*') } | Sort-Object Name -Descending)) {
        $f = $d.FullName
        if ((Test-Path -LiteralPath (Join-Path $f 'rollback.ps1')) -and -not (Test-Path -LiteralPath (Join-Path $f 'KEPT')) -and -not (Test-Path -LiteralPath (Join-Path $f 'ROLLED_BACK')) -and -not (Test-Path -LiteralPath (Join-Path $f 'UNDONE'))) { return $f }
    }
    return ''
}
function Task-Create([DateTime]$when, [string]$script) {
    if ($Fake) { [IO.File]::WriteAllText((FP 'task.txt'), ($when.ToString('s') + '|' + $script)); return }
    $cmd = 'powershell.exe'
    $arg = '-NoProfile -ExecutionPolicy Bypass -File "' + $script + '"'
    $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>CCDC WN-25: put the old firewall back unless the change was kept</Description></RegistrationInfo>
  <Triggers><TimeTrigger><StartBoundary>$($when.ToString('s'))</StartBoundary><Enabled>true</Enabled></TimeTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><ExecutionTimeLimit>PT10M</ExecutionTimeLimit><Enabled>true</Enabled></Settings>
  <Actions Context="Author"><Exec><Command>$cmd</Command><Arguments>$([Security.SecurityElement]::Escape($arg))</Arguments></Exec></Actions>
</Task>
"@
    $xf = Join-Path $Cc.RunDir 'rollback-task.xml'
    [IO.File]::WriteAllText($xf, $xml, [Text.Encoding]::Unicode)
    [void](Invoke-CcProgram -FilePath 'schtasks.exe' -Arguments @('/create', '/tn', $TaskName, '/xml', $xf, '/ru', 'SYSTEM', '/f'))
    if ($LASTEXITCODE -ne 0) { throw "schtasks /create failed (exit $LASTEXITCODE)" }
}

# =============================================================================
# -Undo and -Remove
# =============================================================================
function Find-Run([string]$which) {
    if ($which -eq 'latest') {
        $c = @(Get-ChildItem -LiteralPath $Cc.Out -Force | Where-Object { $_.PSIsContainer -and $_.Name -like ('WN-25_' + $Cc.Host + '_*') -and (Test-Path -LiteralPath (Join-Path $_.FullName 'firewall-before.wfw')) } | Sort-Object Name)
        if ($c.Count -eq 0) { Stop-Cc -Code 2 -Message "no WN-25 run with a firewall export in $($Cc.Out)" }
        return $c[-1].FullName
    }
    if (Test-Path -LiteralPath (Join-Path $which 'firewall-before.wfw')) { return (Resolve-CcPath $which) }
    $t = Join-Path $Cc.Out $which
    if (Test-Path -LiteralPath (Join-Path $t 'firewall-before.wfw')) { return $t }
    Stop-Cc -Code 2 -Message "-Undo: $which has no firewall-before.wfw"
}
if ($Undo) {
    $dir = Find-Run $Undo
    $exp = Join-Path $dir 'firewall-before.wfw'
    Write-CcLog -Level INFO -Message "undo: the firewall as it was before $dir"
    $ok = Invoke-CcChange -Description ('put back the whole firewall from ' + $exp) -Action { Import-Fw $exp }
    if ($ok -and $Cc.Apply) {
        if (Task-Exists) { [void](Invoke-CcChange -Description "delete the rollback task $TaskName" -Action { if ($Fake) { Remove-Item -LiteralPath (FP 'task.txt') -Force } else { [void](Invoke-CcProgram -FilePath 'schtasks.exe' -Arguments @('/delete', '/tn', $TaskName, '/f')) } }) }
        [IO.File]::WriteAllText((Join-Path $dir 'UNDONE'), [DateTime]::UtcNow.ToString('o'))
    }
    if (-not $Cc.Apply) { Write-Host 'Dry run: nothing was put back. Add -Apply.' }
    Write-Host ('Undo of: ' + $dir)
    Complete-Cc
}
if ($Remove) {
    $n = 0
    [void](Invoke-CcChange -Description "remove the rules in group $Group (the ones WN-25 added)" -Action { $script:Removed = Remove-Ours })
    if ($Cc.Apply) { Write-Host ('Removed {0} rules in group {1}. Profiles and the rules WN-25 turned off are unchanged (use -Undo for the whole firewall).' -f $script:Removed, $Group) }
    Complete-Cc
}

# =============================================================================
# Plan
# =============================================================================
Use-CcRunDir
$Dir = $Cc.RunDir
if ($Fake) { $IsDC = Test-Path -LiteralPath (FP 'is-dc') } else { $IsDC = (Get-CcOsInfo).IsDC }

$ShellNames = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'nc.exe', 'nc64.exe', 'ncat.exe', 'socat.exe', 'plink.exe', 'chisel.exe', 'ngrok.exe')
$OddRe = '(\\users\\public\\|\\perflogs\\|\\windows\\temp\\|\\temp\\|\\tmp\\|\\appdata\\|\\downloads\\|\\programdata\\[^\\]+\.(exe|dll)|\$recycle\.bin|\\windows\\tasks\\)'
$BadPorts = @(4444, 4445, 1337, 31337, 5555, 6666, 6667, 6697, 9001, 9999, 12345, 54321)

# Protected list: ports and hosts.
$protPorts = @(); $protHosts = @()
[void](Test-CcProtected -Type host -Value 'load')   # reads the list into $Cc.ProtectedRows
foreach ($e in @($Cc.ProtectedRows)) {
    if ($null -eq $e) { continue }
    if ($e[0] -eq 'port') { $pp = Parse-Port $e[1]; if ($pp) { $protPorts += ($pp.Ports + '/' + $pp.Proto.ToLower()) } else { Write-CcLog -Level WARN -Message "protected list: '$($e[1])' is not a port" } }
    if ($e[0] -eq 'host') { if (Valid-Addr $e[1]) { $protHosts += $e[1] } else { Write-CcLog -Level WARN -Message "protected list: host '$($e[1])' is not an address; names are not used by the firewall" } }
}
$admins = @(@($protHosts) + @($AdminFrom) | Select-Object -Unique)

# want: key "ports/proto" -> reason
$want = @{}; $order = @()
function Want([string]$spec, [string]$why) { $pp = Parse-Port $spec; $k = $pp.Ports + '/' + $pp.Proto.ToLower(); if (-not $want.ContainsKey($k)) { $want[$k] = $why; $script:order += $k } else { $want[$k] += '; ' + $why } }
$exL = @($Exclude | ForEach-Object { $pp = Parse-Port $_; $pp.Ports + '/' + $pp.Proto.ToLower() })
foreach ($p in $protPorts) { Want $p 'protected list (scored)'; if ($exL -contains $p) { Write-CcLog -Level WARN -Message "$p is both protected and in -Exclude: the protected list wins, it is opened" } }
foreach ($p in $Allow) { Want $p '-Allow' }
if ($IsDC) {
    foreach ($p in @('53/tcp', '53/udp', '88/tcp', '88/udp', '135/tcp', '389/tcp', '389/udp', '445/tcp', '464/tcp', '464/udp', '636/tcp', '3268-3269/tcp', '123/udp')) { Want $p 'domain controller (Active Directory)' }
}
$notCsv = New-CcCsv -Name 'not-allowed' -Header @('port', 'address', 'process', 'program', 'why')
$listeners = @(Get-Listeners)
foreach ($l in ($listeners | Sort-Object Port)) {
    $k = ('{0}/{1}' -f $l.Port, (Lc $l.Proto))
    $why = ''
    $ln = Lc $l.Name; $lp = Lc $l.Path
    if ($l.Addr -eq '127.0.0.1' -or $l.Addr -eq '::1') { continue }
    if ($ShellNames -contains $ln) { $why = "$($l.Name) is listening: a shell or tunnel, not a service" }
    elseif ($BadPorts -contains $l.Port) { $why = "port $($l.Port) is a common backdoor port" }
    elseif ($lp -ne '' -and $lp -match $OddRe) { $why = "its program runs from an unusual folder: $($l.Path)" }
    elseif ($l.Port -ge 49152) { $why = 'dynamic port (49152 and up): not opened (a DC gets RPC through its own rule)' }
    elseif ($exL -contains $k) { $why = '-Exclude' }
    if ($why) {
        if ($want.ContainsKey($k)) { Write-CcLog -Level WARN -Message "$k is wanted ($($want[$k])) but $why - it is opened because the list says so" }
        else { Add-CcCsvRow -File $notCsv -Values @($k, $l.Addr, $l.Name, $l.Path, $why); Write-CcLog -Level DEBUG -Message "not opening ${k}: $why"; continue }
    }
    $who = $l.Name; if (-not $who) { $who = 'pid ' + $l.Pid }
    Want $k ("listening now: $who")
}

# Existing inbound allow rules: which to turn off.
$rules = @(Get-InRules)
$dcKeep = '(lsass|dns\.exe|dfsrs|ntfrs|ntdsmsg|netlogon|kdc|kerberos|w32time|dfsr|samss|rpcss|ntds|activedirectory)'
$off = @()
foreach ($r in $rules) {
    if ($r.enabled -ne 'True' -or $r.group -eq $Group) { continue }
    $app = Lc $r.app; $leaf = @($app -split '\\')[-1]
    $anyProto = ($r.protocol -eq '256' -or $r.protocol -eq '' -or (Lc $r.protocol) -eq 'any')
    $anyPort = ($r.lports -eq '' -or $r.lports -eq '*')
    $anyAddr = ($r.raddr -eq '' -or $r.raddr -eq '*')
    $limited = ($r.pkg -or ($r.laddr -and $r.laddr -ne '*') -or ($r.iface -and (Lc $r.iface) -ne 'all') -or ($r.svc -and $r.svc -ne '*'))
    $why = ''
    if ($anyProto -and $anyPort -and $anyAddr -and -not $app -and -not $limited) { $why = 'allows every port, protocol and address' }
    elseif ($ShellNames -contains $leaf) { $why = "allows a shell or tunnel in: $($r.app)" }
    elseif ($app -match $OddRe) { $why = "allows a program in an unusual folder: $($r.app)" }
    else { foreach ($bp in $BadPorts) { if (@($r.lports -split ',' | ForEach-Object { $_.Trim() }) -contains [string]$bp) { $why = "opens backdoor port $bp" } } }
    if (-not $why -and $Strict) {
        if ($IsDC -and ((Lc ($r.app + ' ' + $r.svc + ' ' + $r.group + ' ' + $r.name)) -match $dcKeep)) { continue }
        $why = '-Strict: not one of ours'
    }
    if ($why) { $off += New-Object PSObject -Property @{ R = $r; Why = $why } }
}

# Show the plan.
$planCsv = New-CcCsv -Name plan -Header @('rule', 'protocol', 'ports', 'from', 'why')
$adds = @()
foreach ($k in $order) {
    $pp = Parse-Port $k
    $adds += New-Object PSObject -Property @{ Name = ('CCDC allow ' + $k); Proto = $pp.Proto; Ports = $pp.Ports; From = ''; Why = $want[$k] }
}
if ($IsDC) { $adds += New-Object PSObject -Property @{ Name = 'CCDC allow RPC (DC)'; Proto = 'TCP'; Ports = 'RPC'; From = ''; Why = 'domain controller: RPC dynamic ports' }
             $adds += New-Object PSObject -Property @{ Name = 'CCDC allow RPC endpoint mapper (DC)'; Proto = 'TCP'; Ports = 'RPC-EPMap'; From = ''; Why = 'domain controller' } }
if ($admins.Count -gt 0) { $adds += New-Object PSObject -Property @{ Name = 'CCDC allow admin and scoring hosts'; Proto = 'ANY'; Ports = ''; From = ($admins -join ','); Why = 'protected hosts and -AdminFrom: everything' } }
if (-not $NoPing) { $adds += New-Object PSObject -Property @{ Name = 'CCDC allow ping'; Proto = 'ICMP'; Ports = ''; From = ''; Why = 'ICMP echo (scoring often pings)' } }
foreach ($a in $adds) { Add-CcCsvRow -File $planCsv -Values @($a.Name, $a.Proto, $a.Ports, $a.From, $a.Why) }
$offCsv = New-CcCsv -Name disabled -Header @('rule', 'program', 'ports', 'why', 'result')

$sum = @()
$sum += ('WN-25 Windows firewall  {0}  {1}' -f [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm 'UTC'"), $(if ($Cc.Apply) { 'APPLIED' } else { 'DRY RUN' }))
$sum += ('Host: {0}{1}' -f $Cc.Host, $(if ($IsDC) { '  (domain controller: Active Directory ports kept open)' } else { '' }))
$sum += ''
$sum += 'Profiles: Domain, Private, Public -> ON, block inbound, allow outbound'
$sum += ('Allow in ({0} rules):' -f $adds.Count)
foreach ($a in $adds) { $what = $a.Ports; if ($a.Proto -eq 'ANY') { $what = 'everything from ' + $a.From } elseif ($a.Proto -eq 'ICMP') { $what = 'ping' } else { $what = $a.Ports + '/' + (Lc $a.Proto) }; $sum += ('  {0,-28} {1}' -f $what, $a.Why) }
$na = @(Import-Csv -LiteralPath $notCsv)
if ($na.Count -gt 0) { $sum += ''; $sum += ('NOT opened, though something listens ({0}):' -f $na.Count); foreach ($n in $na) { $sum += ('  {0,-12} {1,-18} {2}' -f $n.port, $n.process, $n.why) } }
if ($off.Count -gt 0) { $sum += ''; $sum += ('Existing rules turned off ({0}):' -f $off.Count); foreach ($o in $off) { $sum += ('  {0}: {1}' -f $o.R.name, $o.Why) } }
if ($admins.Count -eq 0) { $sum += ''; $sum += 'WARNING: no admin or scoring addresses (protected list "host" entries or -AdminFrom). Only the ports above will reach this box.' }

# =============================================================================
# Apply
# =============================================================================
if (-not $Cc.Apply) {
    foreach ($a in $adds) { Write-CcLog -Level WOULD -Message ('add rule ' + $a.Name) ; $Cc.Would++ }
    foreach ($o in $off) { Write-CcLog -Level WOULD -Message ('turn off rule ' + $o.R.name + ' (' + $o.Why + ')'); $Cc.Would++; Add-CcCsvRow -File $offCsv -Values @($o.R.name, $o.R.app, $o.R.lports, $o.Why, 'would turn off') }
    $sum += ''; $sum += 'Dry run: nothing was changed. Check the plan, fill in the protected list, then add -Apply.'
} else {
    if (Task-Exists) {
        $pend = Pending-Run
        if ($pend) {
            Stop-Cc -Code 2 -Message "a firewall change is still waiting to be kept or rolled back ($pend). Run its keep-firewall.ps1 or rollback.ps1, then run this again"
        }
        # The task is left over from a run that was kept or rolled back (for
        # example kept from a window that could not delete it): remove it.
        Write-CcLog -Level INFO -Message "removing a leftover rollback task $TaskName (its run was already kept or rolled back)"
        Task-Delete
    }
    $exp = Join-Path $Dir 'firewall-before.wfw'
    try { Export-Fw $exp } catch { Stop-Cc -Code 4 -Message ('could not export the firewall first, so nothing was changed: ' + $_.Exception.Message) }
    Add-CcUndo -Description 'WN-25 put the whole firewall back' -Command ('netsh advfirewall import {0}' -f (Q $exp))

    # The rollback and keep scripts, written before anything changes.
    $marker = Join-Path $Dir 'ROLLED_BACK'
    $kept = Join-Path $Dir 'KEPT'
    $fakeLine = ''
    if ($Fake) { $fakeLine = "`$env:CCDC_WN25_FAKE = $(Q $Fake)`r`n" }
    $rb = Join-Path $Dir 'rollback.ps1'
    [IO.File]::WriteAllText($rb, @"
# WN-25 rollback: puts back the whole firewall from before $Dir
# The scheduled task $TaskName runs this; you can run it by hand too.
$fakeLine`$exp = $(Q $exp)
if (Test-Path -LiteralPath $(Q $kept)) {
    # Kept: nothing to put back.  Remove the task in case keep could not.
    if (`$env:CCDC_WN25_FAKE) { Remove-Item -LiteralPath (Join-Path `$env:CCDC_WN25_FAKE 'task.txt') -Force -ErrorAction SilentlyContinue } else { schtasks /delete /tn $TaskName /f | Out-Null }
    exit 0
}
if (`$env:CCDC_WN25_FAKE) {
    `$d = `$exp + '.d'; `$f = `$env:CCDC_WN25_FAKE
    if (-not (Test-Path -LiteralPath (Join-Path `$d 'logging.txt'))) { Remove-Item -LiteralPath (Join-Path `$f 'logging.txt') -Force -ErrorAction SilentlyContinue }
    Get-ChildItem -LiteralPath `$d | ForEach-Object { Copy-Item -LiteralPath `$_.FullName -Destination (Join-Path `$f `$_.Name) -Force }
    Remove-Item -LiteralPath (Join-Path `$f 'task.txt') -Force -ErrorAction SilentlyContinue
} else {
    netsh advfirewall import `$exp
    schtasks /delete /tn $TaskName /f
}
[IO.File]::WriteAllText($(Q $marker), [DateTime]::UtcNow.ToString('o'))
"@)
    $kp = Join-Path $Dir 'keep-firewall.ps1'
    [IO.File]::WriteAllText($kp, @"
# WN-25: keep the new firewall.  Run this from a NEW connection (a fresh RDP or
# remote session) - that proves the firewall still lets the team in.
$fakeLine if (Test-Path -LiteralPath $(Q $marker)) { Write-Host 'Too late: the old firewall was already put back. Run WN-25 again.'; exit 1 }
# KEPT first: even if the task cannot be deleted here (not elevated), the
# rollback sees KEPT when it fires and does nothing.
[IO.File]::WriteAllText($(Q $kept), [DateTime]::UtcNow.ToString('o'))
if (`$env:CCDC_WN25_FAKE) { Remove-Item -LiteralPath (Join-Path `$env:CCDC_WN25_FAKE 'task.txt') -Force -ErrorAction SilentlyContinue }
else { schtasks /delete /tn $TaskName /f 2>&1 | Out-Null; if (`$LASTEXITCODE -ne 0) { Write-Host 'Note: the rollback task could not be deleted from this window (not elevated); it will fire, see the change was kept, and do nothing.' } }
Write-Host 'Kept: the rollback is cancelled. The new firewall stays.'
"@)

    $timerOk = $true
    if (-not $NoTimer) {
        $when = (Get-Date).AddMinutes($ConfirmMinutes)
        try { Task-Create $when $rb; Write-CcLog -Level INFO -Message ('rollback task set for {0:HH:mm:ss}' -f $when) }
        catch { $timerOk = $false; Stop-Cc -Code 4 -Message ('could not create the rollback task, so nothing was changed: ' + $_.Exception.Message) }
    }

    $okAll = $true
    # Allow rules first, then the profiles: the box is never closed with
    # nothing open.
    foreach ($a in $adds) {
        $aa = $a
        # Same name, but maybe other addresses (a new -AdminFrom): replace it.
        if (Has-Rule $a.Name) {
            $same = $false
            if ($Fake) { $same = (@(F-Read 'rules.csv' | Where-Object { $_.group -eq $Group -and $_.name -eq $aa.Name -and $_.lports -eq $aa.Ports -and $_.raddr -eq $aa.From }).Count -gt 0) }
            else {
                $wantA = Norm-Addrs $aa.From
                $same = (@(@((Fw).Rules) | Where-Object { $_.Grouping -eq $Group -and $_.Name -eq $aa.Name -and (Nz $_.LocalPorts) -eq $(if ($aa.Ports) { $aa.Ports } else { (Nz $_.LocalPorts) }) -and (Norm-Addrs (Nz $_.RemoteAddresses)) -eq $wantA }).Count -gt 0)
            }
            if ($same) { Write-CcLog -Level DEBUG -Message ('rule already there: ' + $a.Name); continue }
            [void](Invoke-CcChange -Description ('replace rule ' + $a.Name) -Action { if ($Fake) { F-Write 'rules.csv' $RuleCols @(F-Read 'rules.csv' | Where-Object { -not ($_.group -eq $Group -and $_.name -eq $aa.Name) }) } else { (Fw).Rules.Remove($aa.Name) } })
        }
        if (-not (Invoke-CcChange -Description ('add rule ' + $a.Name) -Action { Add-Rule $aa.Name $aa.Proto $aa.Ports $aa.From })) { $okAll = $false }
    }
    foreach ($o in $off) {
        $oo = $o
        $ok = Invoke-CcChange -Description ('turn off rule ' + $o.R.name + ' (' + $o.Why + ')') -Action { Disable-Rule $oo.R }
        $res = 'turned off'; if (-not $ok) { $res = 'FAILED'; $okAll = $false }
        Add-CcCsvRow -File $offCsv -Values @($o.R.name, $o.R.app, $o.R.lports, $o.Why, $res)
    }
    if (-not (Invoke-CcChange -Description 'all profiles on, block inbound, allow outbound' -Action { Set-Profiles })) { $okAll = $false }
    if (-not $NoLog) { [void](Invoke-CcChange -Description 'log dropped connections (pfirewall.log)' -Action { Set-Logging }) }

    $sum += ''
    if (-not $okAll) { $sum += 'SOME CHANGES FAILED: see the log. The rollback timer still covers you.' }
    if ($NoTimer) {
        $sum += 'No rollback timer (-NoTimer).  To put the old firewall back:'
    } else {
        $sum += ('ROLLBACK at {0:HH:mm} unless kept.  From a NEW connection run:' -f $when)
        $sum += ('  powershell -NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $kp)
        $sum += 'Or to put the old firewall back now:'
    }
    $sum += ('  powershell -NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $rb)
    $sum += ('Later, any time:  WN-25-firewall.ps1 -Out {0} -Undo {1} -Apply' -f $Cc.Out, (Split-Path -Leaf $Dir))
}
[IO.File]::WriteAllLines((Join-Path $Dir 'summary.txt'), [string[]]$sum)
if (-not $Quiet -or $Cc.Apply) { foreach ($l in $sum) { Write-Host $l } }
Write-Host ('All results: ' + $Dir)
Complete-Cc
