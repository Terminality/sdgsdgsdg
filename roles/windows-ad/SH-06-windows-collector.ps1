# =============================================================================
# ID:       SH-06
# NAME:     Windows collector
# ROLE:     Windows / AD  (wave 1)
# KIND:     readonly - changes nothing on the host
# VERSION:  1.0.0
#
# PURPOSE
#   One run shows what a Windows host is and what is on it: who can log in and
#   who is an administrator, what is listening, what starts on boot or on a
#   schedule, which security settings are weak or tampered with, and the places
#   a red team usually hides.  The Windows twin of SH-05; run it first on every
#   Windows box.
#
#   Output is layered (rule 17):
#     screen / summary.txt   one page: key facts, a count per section, and only
#                            the HIGH and MEDIUM flags, worst first
#     <section>.csv          everything collected, one file per section
#     flags.csv              every flag including LOW, with the reason
#     raw\*.csv, raw\*.txt   untouched data as it was read, so a parsing
#                            mistake can be told apart from missing data, and
#                            so the run can be replayed (-FromRaw)
#
# USAGE
#   powershell -NoProfile -ExecutionPolicy Bypass -File SH-06-windows-collector.ps1 [options]
#   Run in an elevated window ("Run as administrator").  It works without, but
#   several sections are then incomplete (Security log, process owners and
#   paths, user rights, some Defender settings); the summary says which.
#
# OPTIONS
#   -Profile NAME    card | full | triage   (default: full)
#                      card    quick look, about a minute: system, users,
#                              ports, services, autostart, tasks, security,
#                              firewall, defender
#                      full    card plus processes, connections, sessions,
#                              shares, software, updates, events, drivers,
#                              rights, roles
#                      triage  full plus a copy of the event logs
#   -Only a,b,c      run only these sections (names from -List)
#   -Skip a,b,c      run the profile without these sections
#   -EventHours N    how far back the events section looks (default 24)
#   -MaxFlags N      how many HIGH/MED flags to print on screen (default 30)
#   -FromRaw DIR     read a saved raw folder (from an earlier run, possibly on
#                    another machine) instead of this host.  Used by the tests
#                    and for debugging: send the raw folder, replay it anywhere
#   -List            list the sections and exit
#   Common options (-Out, -DebugLog, -Quiet ...) come from the library.
#
# OUTPUTS  (under the -Out folder; never next to this script)
#   SH-06_<host>_<UTC time>.log                  log of the run
#   SH-06_<host>_<UTC time>\summary.txt          the one-page summary
#   SH-06_<host>_<UTC time>\flags.csv            severity,section,item,detail,time
#   SH-06_<host>_<UTC time>\<section>.csv        see the manual for columns
#   SH-06_<host>_<UTC time>\raw\                 everything as read
#   SH-06_<host>_<UTC time>\logs\*.evtx          event logs (triage only)
#
# WHAT IT CHANGES
#   Nothing.  It only reads.  It never stores a password: registry values
#   whose name looks like a password (Winlogon DefaultPassword and the like)
#   are recorded as "(set; value not recorded)".
#
# DEPENDS ON  (all present on Windows 7 / Server 2008 R2 and later)
#   WMI (Get-WmiObject; Get-CimInstance under PowerShell 7), the registry,
#   netstat, schtasks, netsh, secedit, auditpol, query user, wevtutil, ADSI
#   (WinNT provider) for group members.  Get-MpComputerStatus,
#   Get-MpPreference and Get-SmbServerConfiguration are used when present
#   (Windows 8 / Server 2012 and later) and skipped otherwise.
#
# TESTED ON
#   Replayed raw data under PowerShell 7 on Linux (tests/sh06.Tests.ps1), and
#   the live path there to prove that missing tools only thin a section.
#   NOT yet run on real Windows: run it on a test VM first.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Flags are pointers, not verdicts.  Some will be legitimate on your box.
#   - Text from netsh, schtasks and auditpol is read in its English form.  On
#     a Windows installed in another language some firewall and audit checks
#     come back empty (the raw files still have everything); the summary says
#     when a section could not be read.
#   - On a domain controller the users section lists the domain's users (they
#     are the DC's "local" users) and can be long.  Domain groups beyond
#     Domain/Enterprise/Schema Admins are left to WN-05.
#   - A 32-bit PowerShell on 64-bit Windows sees the 32-bit registry view.
#     Use the normal (64-bit) PowerShell.
#   - It sees what Windows reports.  A kernel rootkit can hide from all of it.
#   - Some attack strings in the checks below are built from pieces on
#     purpose, so antivirus scanning this file does not mistake the check for
#     the attack.
#
# DEBUGGING
#   -DebugLog                print each source read and each section's timing
#   raw\                     shows exactly what was read
#   raw\<name>.error.txt     why a source could not be read
#   -Only NAME               rerun one section
#   -FromRaw <run>\raw       replay a run without touching the host
# =============================================================================
param(
    [switch]$Apply, [string]$Out, [string]$Protected, [switch]$NoProtected,
    [switch]$ForceScored, [switch]$Quiet, [switch]$DebugLog,
    # $Profile is a PowerShell automatic variable, so the option is named
    # -Profile but stored in $Level.
    [Alias('Profile')][string]$Level = 'full',
    [string]$Only = '',
    [string]$Skip = '',
    [int]$EventHours = 24,
    [int]$MaxFlags = 30,
    [string]$FromRaw = '',
    [switch]$List,
    [switch]$Help
)

$SectionHelp = @(
    'system       host facts, domain role, addresses, DNS servers, hosts file',
    'users        local accounts and the members of the admin and remote-access groups',
    'ports        listening ports with the process and program behind each',
    'services     every service: state, start mode, program, account',
    'autostart    Run keys, startup folders, Winlogon, debugger keys, WMI subscriptions',
    'tasks        scheduled tasks and what they run',
    'security     settings red teams weaken: WDigest, UAC, SMBv1, Zerologon, RDP ...',
    'firewall     profile state and inbound rules that allow everything',
    'defender     Defender state and exclusions',
    'processes    every process with its program and command line',
    'connections  live network connections with the process behind each',
    'sessions     who is logged on and who has SMB sessions open',
    'shares       shared folders and who can use them',
    'software     installed programs; remote-access tools flagged',
    'updates      installed updates and the newest date',
    'events       log cleared, accounts created, admins added, services installed',
    'drivers      running drivers loaded from unusual folders',
    'rights       user rights (debug, impersonate, log on) given to unusual accounts',
    'roles        server roles and the key service a box offers',
    'logs         copy of the event logs (triage only; can be large)'
)
$AllSections = @('system','users','ports','services','autostart','tasks','security','firewall','defender','processes','connections','sessions','shares','software','updates','events','drivers','rights','roles','logs')
$ProfileCard = @('system','users','ports','services','autostart','tasks','security','firewall','defender')
$ProfileFull = $ProfileCard + @('processes','connections','sessions','shares','software','updates','events','drivers','rights','roles')
$ProfileTriage = $ProfileFull + @('logs')

if ($Help) {
    Write-Host 'SH-06 Windows collector - read-only inventory of a Windows host'
    Write-Host '  -Profile card|full|triage  how much to collect (default full)'
    Write-Host '  -Only a,b,c / -Skip a,b,c  choose sections (-List shows them)'
    Write-Host '  -EventHours N              events section look-back (default 24)'
    Write-Host '  -MaxFlags N                HIGH/MED flags shown on screen (default 30)'
    Write-Host '  -FromRaw DIR               replay a saved raw folder instead of this host'
    Write-Host '  -Out DIR -Quiet -DebugLog  common options'
    exit 0
}
if ($List) { foreach ($l in $SectionHelp) { Write-Host $l }; exit 0 }

# >>> CCDC-LIB
# Development copy: find lib/lib.ps1 by walking up from this file.  The build
# step (tools/build.sh, LB-03) replaces this whole block with the library
# itself, so the built script is a single standalone file.
$ccDir = Split-Path -Parent $MyInvocation.MyCommand.Path
while ($ccDir -and -not (Test-Path -LiteralPath (Join-Path (Join-Path $ccDir 'lib') 'lib.ps1'))) { $ccDir = Split-Path -Parent $ccDir }
if (-not $ccDir) { Write-Host 'cannot find lib/lib.ps1 above this script'; exit 3 }
. (Join-Path (Join-Path $ccDir 'lib') 'lib.ps1')
# <<< CCDC-LIB

# ---- Options ----------------------------------------------------------------
switch ($Level) {
    'card'   { $Run = $ProfileCard }
    'full'   { $Run = $ProfileFull }
    'triage' { $Run = $ProfileTriage }
    default  { Write-Host "unknown -Profile '$Level' (card, full or triage)"; exit 2 }
}
function Split-List([string]$s) { return @($s -split '[,\s]+' | Where-Object { $_ -ne '' } | ForEach-Object { $_.ToLower() }) }
$onlyList = Split-List $Only
$skipList = Split-List $Skip
foreach ($n in ($onlyList + $skipList)) {
    if (-not ($AllSections -contains $n)) { Write-Host "unknown section '$n' (see -List)"; exit 2 }
}
if ($onlyList.Count -gt 0) { $Run = $onlyList }
$Run = @($AllSections | Where-Object { ($Run -contains $_) -and -not ($skipList -contains $_) })
if ($EventHours -lt 1) { Write-Host '-EventHours must be 1 or more'; exit 2 }

# ---- Start ------------------------------------------------------------------
Initialize-Cc -Id 'SH-06' -Name 'Windows collector' -Kind readonly -Bound $PSBoundParameters
Use-CcRunDir
$RawDir = Join-Path $Cc.RunDir 'raw'
$Replay = $false
if ($FromRaw) {
    if (-not (Test-Path -LiteralPath $FromRaw)) { Stop-Cc -Code 2 -Message "-FromRaw: no folder $FromRaw" }
    $FromRaw = Resolve-CcPath $FromRaw
    $Replay = $true
    Write-CcLog -Level INFO -Message "replaying saved data from $FromRaw - this host is not read"
}
$IsAdmin = $false
if (-not $Replay) {
    $IsAdmin = Test-CcAdmin
    if (-not $IsAdmin) { Write-CcLog -Level WARN -Message 'not elevated: Security log, process owners and paths, user rights and some Defender settings will be incomplete' }
}

# Summary bookkeeping.
$script:Facts = @()          # key-facts lines for the summary
$script:SecTable = @()       # one line per section: name, rows, seconds, notes
$script:SecNote = ''
$script:SecRows = 0
$script:SrcCache = @{}
$script:Sec = ''

function Say([string]$t) { $script:Facts += $t }
function Note([string]$t) { if ($script:SecNote) { $script:SecNote += '; ' + $t } else { $script:SecNote = $t } }
function Flag([string]$sev, [string]$item, [string]$detail) { Add-CcFlag -Severity $sev -Section $script:Sec -Item $item -Detail $detail }
function NewCsv([string]$name, [string[]]$header) { return (New-CcCsv -Name $name -Header $header) }
function Row([string]$file, [object[]]$values) { Add-CcCsvRow -File $file -Values $values; $script:SecRows++ }
function Lc($s) { if ($null -eq $s) { return '' }; return ([string]$s).ToLower() }
function Nz($s) { if ($null -eq $s) { return '' }; return [string]$s }

# ---- Sources: every read goes through these ----------------------------------
# A source is read once, saved under raw\, and read back from the saved copy,
# so a live run and a replay (-FromRaw) take exactly the same path through the
# checks.  Every value comes back as text.

# Read-CsvFile path -> rows.  ReadAllLines detects UTF-8, which Get-Content on
# Windows PowerShell does not.
function Read-CsvFile([string]$path) {
    $lines = @([IO.File]::ReadAllLines($path))
    if ($lines.Count -lt 2) { return @() }
    return @($lines | ConvertFrom-Csv)
}

# Get-Rows -Name n -Props @(...) -Command { objects } -> rows (cached).
#   Props: property names or @{Name=..;Expression={..}} for joined arrays.
function Get-Rows {
    param([string]$Name, [object[]]$Props, [scriptblock]$Command)
    if ($script:SrcCache.ContainsKey($Name)) { return $script:SrcCache[$Name] }
    $file = Join-Path $RawDir ($Name + '.csv')
    $rows = @()
    if ($Replay) {
        $src = Join-Path $FromRaw ($Name + '.csv')
        if (Test-Path -LiteralPath $src) { $rows = @(Read-CsvFile $src); Copy-Item -LiteralPath $src -Destination $file }
        else { Note "$Name not in the replay folder" }
    } else {
        $t0 = [DateTime]::UtcNow
        $objs = @()
        try {
            $ErrorActionPreference = 'Stop'
            $objs = @(& $Command | Select-Object -Property $Props)
        } catch {
            Note ("{0} could not be read" -f $Name)
            [IO.File]::WriteAllText((Join-Path $RawDir ($Name + '.error.txt')), [string]$_.Exception.Message)
            Write-CcLog -Level DEBUG -Message ("source {0} failed: {1}" -f $Name, $_.Exception.Message)
        }
        $names = @()
        foreach ($p in $Props) { if ($p -is [hashtable]) { $names += $p.Name } else { $names += [string]$p } }
        if ($objs.Count -gt 0) { $lines = @($objs | ConvertTo-Csv -NoTypeInformation) }
        else { $lines = @(ConvertTo-CcCsvLine -Values $names) }
        [IO.File]::WriteAllLines($file, [string[]]$lines)
        $rows = @(Read-CsvFile $file)
        Write-CcLog -Level DEBUG -Message ("source {0}: {1} rows in {2:N1}s" -f $Name, $rows.Count, ([DateTime]::UtcNow - $t0).TotalSeconds)
    }
    $script:SrcCache[$Name] = $rows
    return $rows
}

# Get-Text -Name n -Command { program output } -> lines (cached).
function Get-Text {
    param([string]$Name, [scriptblock]$Command)
    $key = 'text:' + $Name
    if ($script:SrcCache.ContainsKey($key)) { return $script:SrcCache[$key] }
    $file = Join-Path $RawDir ($Name + '.txt')
    $lines = @()
    if ($Replay) {
        $src = Join-Path $FromRaw ($Name + '.txt')
        if (Test-Path -LiteralPath $src) { $lines = @([IO.File]::ReadAllLines($src)); Copy-Item -LiteralPath $src -Destination $file }
        else { Note "$Name not in the replay folder" }
    } else {
        try {
            # A program writing to stderr must not stop the collector.
            $ErrorActionPreference = 'Continue'
            $lines = @(& $Command 2>&1 | ForEach-Object { "$_" })
        } catch {
            $lines = @('ERROR: ' + $_.Exception.Message)
            Note ("{0} could not be read" -f $Name)
        }
        [IO.File]::WriteAllLines($file, [string[]]$lines)
    }
    $script:SrcCache[$key] = $lines
    return $lines
}

# Get-Wmi Class [Filter] [Namespace] -> objects.  Get-WmiObject does not exist
# in PowerShell 7, so fall back to the CIM cmdlet there.
function Get-Wmi([string]$Class, [string]$Filter = '', [string]$Namespace = 'root\cimv2') {
    if (Test-CcCommand 'Get-WmiObject') {
        if ($Filter) { return Get-WmiObject -Namespace $Namespace -Class $Class -Filter $Filter -ErrorAction Stop }
        return Get-WmiObject -Namespace $Namespace -Class $Class -ErrorAction Stop
    }
    if ($Filter) { return Get-CimInstance -Namespace $Namespace -ClassName $Class -Filter $Filter -ErrorAction Stop }  # ps2-ok
    return Get-CimInstance -Namespace $Namespace -ClassName $Class -ErrorAction Stop  # ps2-ok
}

# Join an array property into one text field.
function J($v) { if ($null -eq $v) { return '' }; return ((@($v) | ForEach-Object { [string]$_ }) -join ' ') }

# ---- Registry ---------------------------------------------------------------
# Every registry value the checks need is read in one pass into raw\registry.csv
# (Key, Name, Value).  "(key)" rows record that a key exists.

function Format-RegValue([string]$name, $v) {
    if ($null -eq $v) { return '' }
    if ($name -match '(?i)passw|pwd|secret') {
        if ("$v" -ne '') { return '(set; value not recorded)' }
        return ''
    }
    if ($v -is [byte[]]) {
        $n = [Math]::Min($v.Length, 32)
        $hex = ''
        for ($i = 0; $i -lt $n; $i++) { $hex += $v[$i].ToString('x2') }
        if ($v.Length -gt 32) { $hex += '...' }
        return $hex
    }
    if ($v -is [string[]]) { return ($v -join ' | ') }
    return [string]$v
}

function Read-RegKey([string]$Key, [int]$Depth = 0, [string[]]$OnlyNames = @()) {
    $p = 'Registry::' + ($Key -replace '^HKLM\\', 'HKEY_LOCAL_MACHINE\' -replace '^HKU\\', 'HKEY_USERS\')
    $k = $null
    try { $k = Get-Item -LiteralPath $p -ErrorAction Stop } catch { return }
    New-Object PSObject -Property @{ Key = $Key; Name = '(key)'; Value = '' }
    foreach ($n in @($k.GetValueNames())) {
        if ($OnlyNames.Count -gt 0 -and -not ($OnlyNames -contains $n)) { continue }
        $v = $null
        try { $v = $k.GetValue($n, $null, 'DoNotExpandEnvironmentNames') } catch { }
        $shown = $n; if ($shown -eq '') { $shown = '(default)' }
        New-Object PSObject -Property @{ Key = $Key; Name = $shown; Value = (Format-RegValue $n $v) }
    }
    if ($Depth -gt 0) {
        foreach ($s in @($k.GetSubKeyNames())) { Read-RegKey -Key ($Key + '\' + $s) -Depth ($Depth - 1) -OnlyNames $OnlyNames }
    }
}

$CV = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion'
$NT = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$CCS = 'HKLM\SYSTEM\CurrentControlSet'
function Read-AllRegistry {
    $users = @()
    try { $users = @([Microsoft.Win32.Registry]::Users.GetSubKeyNames() | Where-Object { $_ -match '^S-1-5-21-[0-9-]+$' }) } catch { }
    foreach ($k in @("$CV\Run", "$CV\RunOnce", "$CV\RunOnceEx", "$CV\RunServices", "$CV\Policies\Explorer\Run",
                     'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce')) {
        Read-RegKey $k
    }
    foreach ($u in $users) {
        foreach ($k in @('Software\Microsoft\Windows\CurrentVersion\Run', 'Software\Microsoft\Windows\CurrentVersion\RunOnce',
                         'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run', 'Software\Policies\Microsoft\Windows\Installer')) {
            Read-RegKey ("HKU\$u\$k")
        }
    }
    Read-RegKey "$NT\Winlogon" 0 @('Userinit', 'Shell', 'AutoAdminLogon', 'DefaultUserName', 'DefaultDomainName', 'DefaultPassword')
    Read-RegKey "$NT\Image File Execution Options" 1 @('Debugger', 'GlobalFlag')
    Read-RegKey "$NT\SilentProcessExit" 1 @('MonitorProcess')
    Read-RegKey "$NT\Windows" 0 @('AppInit_DLLs', 'LoadAppInit_DLLs')
    Read-RegKey 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows' 0 @('AppInit_DLLs', 'LoadAppInit_DLLs')
    Read-RegKey "$CCS\Control\Lsa" 0 @('RunAsPPL', 'LmCompatibilityLevel', 'NoLMHash', 'RestrictAnonymous', 'RestrictAnonymousSAM', 'EveryoneIncludesAnonymous', 'Security Packages', 'Authentication Packages', 'Notification Packages', 'DisableRestrictedAdmin', 'DisableDomainCreds')
    Read-RegKey "$CCS\Control\SecurityProviders\WDigest" 0 @('UseLogonCredential')
    Read-RegKey "$CCS\Control\Session Manager" 0 @('BootExecute')
    Read-RegKey "$CV\Policies\System" 0 @('EnableLUA', 'ConsentPromptBehaviorAdmin', 'LocalAccountTokenFilterPolicy', 'FilterAdministratorToken')
    Read-RegKey "$CCS\Control\Terminal Server" 0 @('fDenyTSConnections')
    Read-RegKey "$CCS\Control\Terminal Server\WinStations\RDP-Tcp" 0 @('UserAuthentication', 'PortNumber', 'SecurityLayer')
    Read-RegKey "$CCS\Services\LanmanServer\Parameters" 0 @('SMB1', 'RequireSecuritySignature', 'EnableSecuritySignature', 'NullSessionShares', 'NullSessionPipes', 'RestrictNullSessAccess')
    Read-RegKey "$CCS\Services\LanmanWorkstation\Parameters" 0 @('RequireSecuritySignature')
    Read-RegKey "$CCS\Services\mrxsmb10" 0 @('Start')
    Read-RegKey "$CCS\Services\Netlogon\Parameters" 0 @('FullSecureChannelProtection', 'vulnerable_channel_allowlist', 'RequireSignOrSeal')
    Read-RegKey "$CCS\Services\PortProxy" 2
    Read-RegKey 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 0 @('EnableMulticast')
    Read-RegKey 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer' 0 @('AlwaysInstallElevated')
    Read-RegKey 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 0 @('EnableScriptBlockLogging')
    Read-RegKey 'HKLM\SOFTWARE\Microsoft\NetSh'
    Read-RegKey 'HKLM\SOFTWARE\Microsoft\Windows Defender' 0 @('DisableAntiSpyware', 'DisableAntiVirus')
    Read-RegKey 'HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection' 0 @('DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableOnAccessProtection')
    Read-RegKey 'HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions' 1
    Read-RegKey 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' 0 @('DisableAntiSpyware', 'DisableAntiVirus')
    Read-RegKey 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' 0 @('DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableOnAccessProtection')
    Read-RegKey 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions' 1
}

$script:RegIdx = $null
function Get-RegIndex {
    if ($null -ne $script:RegIdx) { return }
    $script:RegIdx = @{}
    $rows = @(Get-Rows -Name registry -Props @('Key', 'Name', 'Value') -Command { Read-AllRegistry })
    foreach ($r in $rows) { $script:RegIdx[(Lc $r.Key) + '|' + (Lc $r.Name)] = Nz $r.Value }
    $script:RegRows = $rows
}
# Reg KEY NAME -> the value text, or $null when the value is not there.
function Reg([string]$Key, [string]$Name) {
    Get-RegIndex
    $k = (Lc $Key) + '|' + (Lc $Name)
    if ($script:RegIdx.ContainsKey($k)) { return $script:RegIdx[$k] }
    return $null
}
# RegRows KEY [-Under] -> rows of that key (or of every key below it).
function RegRows([string]$Key, [switch]$Under) {
    Get-RegIndex
    $lk = Lc $Key
    return @($script:RegRows | Where-Object { $_.Name -ne '(key)' -and ((Lc $_.Key) -eq $lk -or ($Under -and (Lc $_.Key).StartsWith($lk + '\'))) })
}
function RegKeys([string]$Key) {
    Get-RegIndex
    $lk = Lc $Key
    return @($script:RegRows | Where-Object { $_.Name -eq '(key)' -and (Lc $_.Key).StartsWith($lk + '\') })
}

# ---- Shared checks ------------------------------------------------------------
# Command lines and paths that are almost never legitimate (strong) or worth a
# look (weak).  Some words are joined from pieces so that antivirus scanning
# this file does not take the check for the attack it looks for.
$p1 = 'download' + 'str'; $p2 = 'net' + '\.web' + 'client'; $p3 = 'from' + 'base64'; $p4 = 'invoke-' + 'expression'
$StrongRe = '(-e(nc|ncodedcommand)?\s+[a-z0-9+/=]{24,}|' + $p1 + '|downloadfile|' + $p2 + '|' + $p3 + '|' + $p4 + '|\biex\b|invoke-webrequest|\biwr\b|start-bitstransfer|bitsadmin.*/transfer|certutil.*(urlcache|-decode)|mshta(\.exe)?\s+(http|javascript|vbscript)|regsvr32.*/i:|rundll32.*(javascript|http)|-w(indowstyle)?\s+h(idden)?\b.*-nop|-nop.*-w(indowstyle)?\s+h(idden)?\b|\bnc(at|64)?(\.exe)?\s+.*-e\s|https?://)'  # ps2-ok (a pattern, not a call)
$WeakRe = '(\\appdata\\|\\temp\\|\\tmp\\|\\users\\public\\|\\perflogs\\|\\windows\\tasks\\|\\windows\\debug\\|\$recycle\.bin|\\programdata\\[^\\]+\.(exe|dll|ps1|bat|cmd|vbs|js|hta)$)'
function Test-Susp([string]$s) {
    $l = Lc $s
    if ($l -eq '') { return '' }
    if ($l -match $StrongRe) { return 'strong' }
    if ($l -match $WeakRe) { return 'weak' }
    return ''
}
$ShellNames = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'powershell_ise.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe', 'msbuild.exe', 'installutil.exe')
$NetToolNames = @('nc.exe', 'nc64.exe', 'ncat.exe', 'socat.exe', 'plink.exe', 'chisel.exe', 'ngrok.exe', 'frpc.exe')
$BadPorts = @(4444, 4445, 1337, 31337, 5555, 6666, 6667, 6697, 9001, 9999, 12345, 54321)
$ServerParents = @('w3wp.exe', 'httpd.exe', 'nginx.exe', 'php-cgi.exe', 'java.exe', 'tomcat.exe', 'tomcat8.exe', 'tomcat9.exe', 'sqlservr.exe', 'inetinfo.exe')

# Processes (shared by ports, connections and processes).
function Get-Procs {
    return @(Get-Rows -Name processes -Props @('ProcessId', 'ParentProcessId', 'Name', 'ExecutablePath', 'CommandLine', 'CreationDate', 'Owner') -Command {
        foreach ($p in @(Get-Wmi Win32_Process)) {
            $owner = ''
            if ($p.PSObject.Methods['GetOwner']) {
                try { $o = $p.GetOwner(); if ($o.User) { $owner = $o.Domain + '\' + $o.User } } catch { }
            }
            $p | Add-Member -MemberType NoteProperty -Name Owner -Value $owner -Force -PassThru
        }
    })
}
$script:ProcByPid = $null
function Proc([string]$procId) {
    if ($null -eq $script:ProcByPid) {
        $script:ProcByPid = @{}
        foreach ($p in @(Get-Procs)) { $script:ProcByPid[[string]$p.ProcessId] = $p }
    }
    if ($script:ProcByPid.ContainsKey($procId)) { return $script:ProcByPid[$procId] }
    return $null
}

# netstat -ano, parsed.  State words are localised; a TCP socket whose remote
# end is port 0 is listening whatever the word says.
function Get-Sockets {
    if ($script:SrcCache.ContainsKey('sockets')) { return $script:SrcCache['sockets'] }
    $out = @()
    foreach ($line in @(Get-Text -Name netstat -Command { netstat -ano })) {
        $f = @(($line.Trim()) -split '\s+')
        if ($f.Count -lt 4) { continue }
        $proto = $f[0].ToUpper()
        if ($proto -ne 'TCP' -and $proto -ne 'UDP') { continue }
        if ($proto -eq 'TCP' -and $f.Count -ge 5) { $state = $f[3]; $procId = $f[4] }
        elseif ($proto -eq 'UDP') { $state = ''; $procId = $f[$f.Count - 1] }
        else { continue }
        $li = $f[1].LastIndexOf(':'); $ri = $f[2].LastIndexOf(':')
        if ($li -lt 0 -or $ri -lt 0) { continue }
        $laddr = $f[1].Substring(0, $li).Trim('[', ']'); $lport = $f[1].Substring($li + 1)
        $raddr = $f[2].Substring(0, $ri).Trim('[', ']'); $rport = $f[2].Substring($ri + 1)
        $listen = ($proto -eq 'UDP') -or ($rport -eq '0')
        $out += (New-Object PSObject -Property @{ Proto = $proto; LAddr = $laddr; LPort = $lport; RAddr = $raddr; RPort = $rport; State = $state; Pid = $procId; Listen = $listen })
    }
    $script:SrcCache['sockets'] = $out
    return $out
}

# Services (shared by services, ports and roles).
function Get-Services {
    return @(Get-Rows -Name services -Props @('Name', 'DisplayName', 'State', 'StartMode', 'PathName', 'StartName', 'ProcessId') -Command { Get-Wmi Win32_Service })
}
$script:SvcByPid = $null
function SvcNames([string]$procId) {
    if ($null -eq $script:SvcByPid) {
        $script:SvcByPid = @{}
        foreach ($s in @(Get-Services)) {
            if ($s.ProcessId -and $s.ProcessId -ne '0') {
                if ($script:SvcByPid.ContainsKey($s.ProcessId)) { $script:SvcByPid[$s.ProcessId] += ',' + $s.Name } else { $script:SvcByPid[$s.ProcessId] = $s.Name }
            }
        }
    }
    if ($script:SvcByPid.ContainsKey($procId)) { return $script:SvcByPid[$procId] }
    return ''
}

# Program path from a service or task command line: quoted part, or up to
# the first .exe.
function Get-ExePath([string]$cmd) {
    $c = (Nz $cmd).Trim()
    if ($c.StartsWith('"')) { $e = $c.IndexOf('"', 1); if ($e -gt 0) { return $c.Substring(1, $e - 1) } }
    $m = [regex]::Match($c, '^(.+?\.(exe|com|bat|cmd))(\s|$)', 'IgnoreCase')
    if ($m.Success) { return $m.Groups[1].Value }
    return ($c -split '\s+')[0]
}

$script:OsRow = $null
function Get-OsRow {
    if ($null -eq $script:OsRow) {
        $r = @(Get-Rows -Name os -Props @('Caption', 'Version', 'BuildNumber', 'ProductType', 'OSArchitecture', 'LastBootUpTime', 'InstallDate') -Command { Get-Wmi Win32_OperatingSystem })
        if ($r.Count -gt 0) { $script:OsRow = $r[0] } else { $script:OsRow = New-Object PSObject -Property @{ Caption = 'unknown'; Version = ''; BuildNumber = '0'; ProductType = '0' } }
    }
    return $script:OsRow
}
function Build { $b = 0; [void][int]::TryParse((Nz (Get-OsRow).BuildNumber), [ref]$b); return $b }
function IsDC { return ((Nz (Get-OsRow).ProductType) -eq '2') }
function IsServer { $t = Nz (Get-OsRow).ProductType; return ($t -eq '2' -or $t -eq '3') }

# WMI dates (20260101120000.000000+000) -> yyyy-MM-dd HH:mm, or the text as is.
function WDate([string]$s) {
    if ($s -match '^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)') { return ('{0}-{1}-{2} {3}:{4}' -f $matches[1], $matches[2], $matches[3], $matches[4], $matches[5]) }
    return $s
}

# =============================================================================
# Sections
# =============================================================================

function S-system {
    $os = Get-OsRow
    $cs = @(Get-Rows -Name computer -Props @('Name', 'Domain', 'PartOfDomain', 'DomainRole', 'Manufacturer', 'Model', 'TotalPhysicalMemory') -Command { Get-Wmi Win32_ComputerSystem })
    $f = NewCsv facts @('key', 'value')
    $role = @{ '0' = 'standalone workstation'; '1' = 'domain workstation'; '2' = 'standalone server'; '3' = 'member server'; '4' = 'backup domain controller'; '5' = 'domain controller' }
    $dr = ''; $dom = ''; $name = $Cc.Host
    if ($cs.Count -gt 0) { $dr = $role[(Nz $cs[0].DomainRole)]; $dom = Nz $cs[0].Domain; $name = Nz $cs[0].Name }
    foreach ($kv in @(@('hostname', $name), @('os', $os.Caption), @('version', $os.Version), @('build', $os.BuildNumber),
                      @('architecture', $os.OSArchitecture), @('domain', $dom), @('domain_role', $dr),
                      @('last_boot', (WDate (Nz $os.LastBootUpTime))), @('installed', (WDate (Nz $os.InstallDate))),
                      @('collector_elevated', $IsAdmin), @('powershell', $PSVersionTable.PSVersion.ToString()),
                      @('time_utc', [DateTime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")))) {
        Row $f $kv
    }
    Say ('Host: {0}  {1} (build {2})  {3}  domain {4}' -f $name, $os.Caption, $os.BuildNumber, $dr, $dom)
    if ($Replay) { Say "Replayed from: $FromRaw" }

    $a = NewCsv addresses @('adapter', 'mac', 'addresses', 'gateway', 'dns_servers', 'dhcp')
    $ips = @()
    foreach ($n in @(Get-Rows -Name nics -Props @('Description', 'MACAddress', @{Name = 'IPAddress'; Expression = { J $_.IPAddress } }, @{Name = 'Gateway'; Expression = { J $_.DefaultIPGateway } }, @{Name = 'DNS'; Expression = { J $_.DNSServerSearchOrder } }, 'DHCPEnabled') -Command { Get-Wmi Win32_NetworkAdapterConfiguration 'IPEnabled=TRUE' })) {
        Row $a @($n.Description, $n.MACAddress, $n.IPAddress, $n.Gateway, $n.DNS, $n.DHCPEnabled)
        $ips += @((Nz $n.IPAddress) -split ' ' | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' })
    }
    if ($ips.Count -gt 0) { Say ('Addresses: ' + ($ips -join ', ')) }

    # hosts file: any real entry is worth a look; one that sends a common
    # update, security or Microsoft name elsewhere is a red-team trick.
    $h = NewCsv hosts_file @('address', 'names')
    foreach ($l in @(Get-Text -Name hosts -Command { $p = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'; if (Test-Path -LiteralPath $p) { Get-Content -LiteralPath $p } })) {
        $t = ($l -replace '#.*$', '').Trim()
        if ($t -eq '' -or $t.StartsWith('ERROR:')) { continue }
        $parts = @($t -split '\s+')
        if ($parts.Count -lt 2) { continue }
        $names = ($parts[1..($parts.Count - 1)] -join ' ')
        Row $h @($parts[0], $names)
        if ((Lc $names) -match '(microsoft|windowsupdate|windows\.com|update|defender|virustotal|symantec|mcafee|kaspersky|sophos|crowdstrike|sentinelone)') {
            Flag HIGH "hosts: $names" ("hosts file sends {0} to {1}" -f $names, $parts[0])
        } elseif ((Lc $names) -notmatch '^localhost') {
            Flag MED "hosts: $names" ("hosts file entry {0} -> {1}" -f $names, $parts[0])
        }
    }
}

# Text that looks like it holds a password ("pwd: x", "password=x").
$PwRe = '(pass(word)?|pwd|pw)\s*(is\s*)?[:=]|(hidden: password)'
function Hide-Pw($s) { if ((Lc $s) -match $PwRe -and (Lc $s) -notmatch 'hidden: password') { return '(hidden: password-like text)' }; return (Nz $s) }

function S-users {
    $dc = IsDC
    $f = NewCsv users @('name', 'sid', 'enabled', 'locked', 'password_required', 'password_expires', 'description')
    $flt = 'LocalAccount=True'
    if ($dc) { $flt = "Domain='" + ($env:USERDOMAIN -replace "'", '') + "'"; Note 'domain controller: domain users listed' }
    # A description that looks like it holds a password is replaced before it
    # is saved anywhere, raw\ included.
    $users = @(Get-Rows -Name users -Props @('Name', 'SID', 'Disabled', 'Lockout', 'PasswordRequired', 'PasswordExpires', @{Name = 'Description'; Expression = { Hide-Pw $_.Description } }) -Command { Get-Wmi Win32_UserAccount $flt })
    $enabled = @()
    foreach ($u in $users) {
        $en = ((Nz $u.Disabled) -ne 'True')
        Row $f @($u.Name, $u.SID, $en, $u.Lockout, $u.PasswordRequired, $u.PasswordExpires, (Hide-Pw $u.Description))
        $rid = ((Nz $u.SID) -split '-')[-1]
        if ($en) { $enabled += $u.Name }
        if ($rid -eq '501' -and $en) { Flag HIGH $u.Name 'the Guest account is enabled' }
        if ($rid -eq '500' -and $en) { Flag LOW $u.Name 'the built-in Administrator account is enabled' }
        if ($en -and (Nz $u.Name).EndsWith('$')) { Flag HIGH $u.Name 'enabled account whose name ends in $ (hidden from some listings)' }
        if ($en -and (Nz $u.PasswordRequired) -eq 'False') { Flag MED $u.Name 'account may have an empty password (password not required)' }
        if ((Lc $u.Description) -match $PwRe) { Flag HIGH $u.Name 'the description field looks like it holds a password (it is not copied here; read it in Windows, then clear it)' }
    }
    Say ('Enabled accounts ({0}): {1}' -f $enabled.Count, (($enabled | Select-Object -First 15) -join ', '))

    # Members of the groups that give control of the box, found by well-known
    # SID so the names work in any language.
    $g = NewCsv admins @('group', 'group_sid', 'member', 'member_class')
    $members = @(Get-Rows -Name group_members -Props @('Group', 'GroupSid', 'Member', 'Class') -Command {
        $want = @('S-1-5-32-544', 'S-1-5-32-555', 'S-1-5-32-551', 'S-1-5-32-580', 'S-1-5-32-549', 'S-1-5-32-548', 'S-1-5-32-578')
        $groups = @(Get-Wmi Win32_Group "LocalAccount=True" | Where-Object { $want -contains $_.SID })
        if ($dc) {
            $groups += @(Get-Wmi Win32_Group ("Domain='" + ($env:USERDOMAIN -replace "'", '') + "'") | Where-Object { $_.SID -match '-(512|518|519)$' -or $_.Name -eq 'DnsAdmins' })
        }
        foreach ($gr in $groups) {
            $obj = [ADSI]('WinNT://' + $gr.Domain + '/' + $gr.Name + ',group')
            foreach ($m in @($obj.psbase.Invoke('Members'))) {
                $path = $m.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $m, $null)
                $cls = $m.GetType().InvokeMember('Class', 'GetProperty', $null, $m, $null)
                $nm = ($path -replace '^WinNT://', '') -replace '/', '\'
                New-Object PSObject -Property @{ Group = $gr.Name; GroupSid = $gr.SID; Member = $nm; Class = $cls }
            }
        }
    })
    $admins = @(); $rdp = @()
    foreach ($m in $members) {
        Row $g @($m.Group, $m.GroupSid, $m.Member, $m.Class)
        $short = ((Nz $m.Member) -split '\\')[-1]
        if ($m.GroupSid -eq 'S-1-5-32-544') { $admins += $short; Flag LOW $m.Member 'member of Administrators: check it is one of yours' }
        if ($m.GroupSid -eq 'S-1-5-32-555') { $rdp += $short; Flag LOW $m.Member 'member of Remote Desktop Users' }
        if ((Nz $m.GroupSid) -match '-(512|519)$') { $admins += $short; Flag LOW $m.Member ('member of ' + $m.Group) }
        if ((Lc $m.Member) -match '\\(guest|everyone|anonymous logon|authenticated users|domain users|users)$' -and ($m.GroupSid -eq 'S-1-5-32-544' -or $m.GroupSid -eq 'S-1-5-32-555' -or (Nz $m.GroupSid) -match '-(512|519)$')) {
            Flag HIGH $m.Member ("{0} is in {1}: everyone in it gets that access" -f $m.Member, $m.Group)
        }
    }
    if ($members.Count -eq 0 -and -not $Replay) { Note 'group members could not be read' }
    Say ('Administrators: ' + (($admins | Select-Object -Unique) -join ', '))
    if ($rdp.Count -gt 0) { Say ('Remote Desktop Users: ' + ($rdp -join ', ')) }
}

function S-ports {
    $f = NewCsv ports @('proto', 'address', 'port', 'pid', 'process', 'program', 'services')
    $seen = @{}
    $list = @()
    foreach ($s in @(Get-Sockets | Where-Object { $_.Listen })) {
        $p = Proc $s.Pid
        $name = ''; $exe = ''
        if ($p) { $name = Nz $p.Name; $exe = Nz $p.ExecutablePath }
        if ($s.Pid -eq '4') { $name = 'System' }
        $svc = SvcNames $s.Pid
        Row $f @($s.Proto, $s.LAddr, $s.LPort, $s.Pid, $name, $exe, $svc)
        $key = $s.Proto + '/' + $s.LPort + '/' + $s.Pid
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = 1
        $port = 0; [void][int]::TryParse($s.LPort, [ref]$port)
        $item = ('{0}/{1} {2}' -f $s.LPort, (Lc $s.Proto), $name)
        if ($s.Proto -eq 'TCP' -and $s.LAddr -ne '127.0.0.1' -and $s.LAddr -ne '::1' -and $port -lt 49152) { $list += ('{0}/tcp {1}' -f $s.LPort, $name) }
        $ln = Lc $name
        if ($ShellNames -contains $ln -or $NetToolNames -contains $ln) { Flag HIGH $item "$name is listening on a port: a shell or tunnel waiting for connections" }
        elseif ($BadPorts -contains $port) { Flag HIGH $item "port $port is a common backdoor port" }
        elseif ((Test-Susp $exe) -ne '') { Flag HIGH $item "listening program runs from an unusual folder: $exe" }
        elseif ($port -eq 23 -and $s.Proto -eq 'TCP') { Flag MED $item 'Telnet is listening (passwords sent in clear text)' }
        elseif ($port -eq 21 -and $s.Proto -eq 'TCP') { Flag LOW $item 'FTP is listening' }
        elseif ($s.Proto -eq 'TCP' -and -not $p -and $s.Pid -ne '4' -and $s.Pid -ne '0' -and $s.LAddr -ne '127.0.0.1') { Flag LOW $item "listening process $($s.Pid) not found (ended, or hidden)" }
    }
    $u = @($list | Select-Object -Unique)
    Say ('Listening TCP ({0}): {1}' -f $u.Count, (($u | Select-Object -First 25) -join ', '))
}

function S-services {
    $f = NewCsv services @('name', 'display_name', 'state', 'start_mode', 'account', 'program', 'command')
    $dc = IsDC
    $running = 0
    foreach ($s in @(Get-Services)) {
        $exe = Get-ExePath $s.PathName
        Row $f @($s.Name, $s.DisplayName, $s.State, $s.StartMode, $s.StartName, $exe, $s.PathName)
        if ($s.State -eq 'Running') { $running++ }
        $item = $s.Name
        $sus = Test-Susp $s.PathName
        $ln = Lc ([IO.Path]::GetFileName($exe))
        if ($sus -eq 'strong' -or $ShellNames -contains $ln -or $NetToolNames -contains $ln) {
            Flag HIGH $item ("service runs a command line, not a service program: {0}" -f $s.PathName)
        } elseif ($sus -eq 'weak') {
            Flag HIGH $item ("service program is in an unusual folder: {0}" -f $exe)
        } else {
            # Unquoted path with a space, outside Windows: anyone who can write
            # to the first folder can run code as the service (privilege escalation).
            $pn = (Nz $s.PathName).Trim()
            if ($pn -ne '' -and -not $pn.StartsWith('"') -and $exe.Contains(' ') -and (Lc $exe) -notmatch '^[a-z]:\\windows\\' -and $s.StartMode -ne 'Disabled') {
                Flag MED $item ("unquoted service path with spaces: {0}" -f $pn)
            }
        }
        $acct = Lc $s.StartName
        if ($acct -ne '' -and $acct -ne 'localsystem' -and -not $acct.StartsWith('nt authority\') -and -not $acct.StartsWith('nt service\') -and $s.StartMode -ne 'Disabled') {
            Flag LOW $item ("runs as the account {0}: changing that account's password breaks this service unless the service is updated too" -f $s.StartName)
        }
        $ls = Lc $s.Name
        if ($s.State -eq 'Running') {
            if ($ls -eq 'remoteregistry') { Flag MED $item 'Remote Registry is running (lets others read and change the registry over the network)' }
            elseif ($ls -eq 'tlntsvr') { Flag MED $item 'Telnet server is running' }
            elseif ($ls -eq 'spooler' -and $dc) { Flag MED $item 'Print Spooler runs on a domain controller (PrintNightmare); stop it unless printing is scored' }
            elseif ($ls -eq 'snmp') { Flag LOW $item 'SNMP service is running: check the community names' }
        }
        if (($ls -eq 'eventlog' -or $ls -eq 'windefend') -and $s.State -ne 'Running' -and $s.State -ne '') {
            Flag HIGH $item ("{0} is {1}" -f $s.DisplayName, $s.State)
        }
    }
    Say ('Services running: ' + $running)
}

function S-autostart {
    $f = NewCsv autostart @('where', 'name', 'command')
    # Run keys, for the machine and every loaded user.
    foreach ($r in @(RegRows 'HKLM' -Under)) {
        $k = Lc $r.Key
        if ($k -notmatch '\\(run|runonce|runonceex|runservices)$') { continue }
        Row $f @($r.Key, $r.Name, $r.Value)
        $s = Test-Susp $r.Value
        if ($s -eq 'strong') { Flag HIGH $r.Name ("Run key starts a suspicious command: {0}" -f $r.Value) }
        elseif ($s -eq 'weak') { Flag HIGH $r.Name ("Run key starts a program in an unusual folder: {0}" -f $r.Value) }
        else { Flag LOW $r.Name ("starts at logon: {0}" -f $r.Value) }
    }
    foreach ($r in @(RegRows 'HKU' -Under)) {
        if ((Lc $r.Key) -notmatch '\\(run|runonce)$') { continue }
        Row $f @($r.Key, $r.Name, $r.Value)
        $s = Test-Susp $r.Value
        if ($s -ne '') { Flag HIGH $r.Name ("user Run key starts: {0}" -f $r.Value) }
        else { Flag LOW $r.Name ("starts at this user's logon: {0}" -f $r.Value) }
    }
    # Winlogon.
    $ui = Reg "$NT\Winlogon" 'Userinit'; $sh = Reg "$NT\Winlogon" 'Shell'
    Row $f @('Winlogon', 'Userinit', $ui); Row $f @('Winlogon', 'Shell', $sh)
    if ($null -ne $ui -and ((Lc $ui).Trim().TrimEnd(',') -replace '^%systemroot%', 'c:\windows' -replace '^%windir%', 'c:\windows') -notmatch '^(c:\\windows\\system32\\)?userinit\.exe$') {
        Flag HIGH 'Winlogon Userinit' "logon runs more than userinit.exe: $ui"
    }
    if ($null -ne $sh -and (Lc $sh).Trim() -ne 'explorer.exe' -and (Lc $sh).Trim() -ne '') { Flag HIGH 'Winlogon Shell' "the logon shell is not explorer.exe: $sh" }
    # Debugger keys: a "debugger" for sethc.exe or utilman.exe gives a SYSTEM
    # shell at the logon screen; for any program it runs instead of it.
    foreach ($r in @(RegRows "$NT\Image File Execution Options" -Under)) {
        $prog = ($r.Key -split '\\')[-1]
        if ($r.Name -eq 'Debugger') { Row $f @('IFEO debugger', $prog, $r.Value); Flag HIGH $prog ("debugger set: starting {0} runs {1}" -f $prog, $r.Value) }
        if ($r.Name -eq 'GlobalFlag' -and $r.Value -eq '512') { Row $f @('IFEO GlobalFlag', $prog, $r.Value) }
    }
    foreach ($r in @(RegRows "$NT\SilentProcessExit" -Under)) {
        if ($r.Name -eq 'MonitorProcess') { $prog = ($r.Key -split '\\')[-1]; Row $f @('SilentProcessExit', $prog, $r.Value); Flag HIGH $prog ("when {0} exits, {1} is started" -f $prog, $r.Value) }
    }
    foreach ($k in @("$NT\Windows", 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
        $dll = Reg $k 'AppInit_DLLs'; $load = Reg $k 'LoadAppInit_DLLs'
        if ($dll -and $dll.Trim() -ne '') {
            Row $f @('AppInit_DLLs', $k, $dll)
            if ($load -eq '1') { Flag HIGH 'AppInit_DLLs' "loaded into every program: $dll" } else { Flag MED 'AppInit_DLLs' "set but not loaded (LoadAppInit_DLLs off): $dll" }
        }
    }
    $be = Reg "$CCS\Control\Session Manager" 'BootExecute'
    if ($be -and (Lc $be).Trim() -ne 'autocheck autochk *') { Row $f @('BootExecute', '', $be); Flag MED 'BootExecute' "runs at boot before Windows starts: $be" }
    # netsh helper DLLs load whenever netsh runs.
    $defaultNetsh = @('authfwcfg.dll', 'dhcpcmonitor.dll', 'dot3cfg.dll', 'fwcfg.dll', 'hnetmon.dll', 'ifmon.dll', 'napmontr.dll', 'netiohlp.dll', 'netprofm.dll', 'nettrace.dll', 'nshhttp.dll', 'nshipsec.dll', 'nshwfp.dll', 'p2pnetsh.dll', 'rasmontr.dll', 'rpcnsh.dll', 'wcnnetsh.dll', 'whhelper.dll', 'wlancfg.dll', 'wshelper.dll', 'wwancfg.dll', 'peerdistsh.dll', 'mprmsg.dll', 'dhcpmonitor.dll', 'wcnnetsh.dll', 'ipmontr.dll', 'ippromon.dll', 'ipxmontr.dll', 'ipxpromn.dll', 'nshhttp.dll')
    foreach ($r in @(RegRows 'HKLM\SOFTWARE\Microsoft\NetSh')) {
        Row $f @('netsh helper', $r.Name, $r.Value)
        if (-not ($defaultNetsh -contains (Lc ([IO.Path]::GetFileName($r.Value))))) { Flag MED $r.Name "unknown netsh helper DLL: $($r.Value)" }
    }
    # LSA packages load into lsass.exe and can read passwords.
    $defLsa = @('kerberos', 'msv1_0', 'schannel', 'wdigest', 'tspkg', 'pku2u', 'cloudap', 'negoexts', 'livessp', 'scecli', 'rassfm', '""', '')
    foreach ($n in @('Security Packages', 'Authentication Packages', 'Notification Packages')) {
        $v = Reg "$CCS\Control\Lsa" $n
        if ($null -eq $v) { continue }
        Row $f @('LSA', $n, $v)
        foreach ($pk in @($v -split '\s*\|\s*|\s+')) { if ($pk -ne '' -and -not ($defLsa -contains (Lc $pk))) { Flag MED "LSA $n" "unknown package loaded into lsass: $pk" } }
    }
    # Startup folders.
    foreach ($s in @(Get-Rows -Name startup_files -Props @('Path', 'LastWrite') -Command {
            $dirs = @((Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp'))
            $ud = Split-Path -Parent $env:PUBLIC
            foreach ($u in @(Get-ChildItem -LiteralPath $ud -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer })) {
                $dirs += (Join-Path $u.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup')
            }
            foreach ($d in $dirs) {
                if (Test-Path -LiteralPath $d) {
                    foreach ($i in @(Get-ChildItem -LiteralPath $d -Force -ErrorAction SilentlyContinue)) {
                        if (-not $i.PSIsContainer -and $i.Name -ne 'desktop.ini') { New-Object PSObject -Property @{ Path = $i.FullName; LastWrite = $i.LastWriteTime.ToString('yyyy-MM-dd HH:mm') } }
                    }
                }
            }
        })) {
        Row $f @('Startup folder', (Split-Path -Leaf $s.Path), $s.Path)
        Flag MED (Split-Path -Leaf $s.Path) ("in a Startup folder (runs at logon): {0}" -f $s.Path)
    }
    # WMI event subscriptions run code on a trigger and survive reboots.
    foreach ($c in @(Get-Rows -Name wmi_consumers -Props @('Class', 'Name', 'Command') -Command {
            foreach ($x in @(Get-Wmi CommandLineEventConsumer '' 'root\subscription')) { New-Object PSObject -Property @{ Class = 'CommandLine'; Name = $x.Name; Command = ((Nz $x.ExecutablePath) + ' ' + (Nz $x.CommandLineTemplate)).Trim() } }
            foreach ($x in @(Get-Wmi ActiveScriptEventConsumer '' 'root\subscription')) { $t = Nz $x.ScriptText; if ($t.Length -gt 300) { $t = $t.Substring(0, 300) + '...' }; New-Object PSObject -Property @{ Class = 'ActiveScript'; Name = $x.Name; Command = $t } }
        })) {
        Row $f @('WMI subscription', $c.Name, $c.Command)
        Flag HIGH ('WMI ' + $c.Name) ("WMI event subscription runs: {0}" -f $c.Command)
    }
    # Accessibility programs replaced by a shell (sticky-keys backdoor).
    $files = @(Get-Rows -Name system_files -Props @('Name', 'Path', 'Size', 'Sha256') -Command {
        $s32 = Join-Path $env:SystemRoot 'System32'
        foreach ($n in @('sethc.exe', 'utilman.exe', 'osk.exe', 'magnify.exe', 'narrator.exe', 'displayswitch.exe', 'atbroker.exe', 'cmd.exe', 'powershell.exe', 'explorer.exe')) {
            $p = Join-Path $s32 $n
            if ($n -eq 'powershell.exe') { $p = Join-Path $s32 'WindowsPowerShell\v1.0\powershell.exe' }
            if ($n -eq 'explorer.exe') { $p = Join-Path $env:SystemRoot 'explorer.exe' }
            if (Test-Path -LiteralPath $p) { New-Object PSObject -Property @{ Name = $n; Path = $p; Size = (Get-Item -LiteralPath $p).Length; Sha256 = (Get-CcSha256 -Path $p) } }
        }
    })
    $shells = @{}
    foreach ($x in $files) { if (@('cmd.exe', 'powershell.exe', 'explorer.exe') -contains (Lc $x.Name) -and $x.Sha256) { $shells[$x.Sha256] = $x.Name } }
    foreach ($x in $files) {
        if (@('cmd.exe', 'powershell.exe', 'explorer.exe') -contains (Lc $x.Name)) { continue }
        if ($x.Sha256 -and $shells.ContainsKey($x.Sha256)) { Flag HIGH $x.Name ("{0} has been replaced by {1}: a SYSTEM shell at the logon screen" -f $x.Path, $shells[$x.Sha256]) }
    }
}

function S-tasks {
    $f = NewCsv tasks @('task', 'status', 'run_as', 'author', 'command', 'next_run')
    # /v /fo csv columns by position, so other languages work too:
    #   1 TaskName 2 Next Run Time 3 Status 7 Author 8 Task To Run 14 Run As User
    $lines = @(Get-Text -Name schtasks -Command { schtasks /query /fo csv /v })
    $hdr = @(); for ($i = 0; $i -lt 30; $i++) { $hdr += ('c' + $i) }
    $rows = @($lines | Where-Object { $_ -match '^"' } | ConvertFrom-Csv -Header $hdr)
    $seen = @{}; $count = 0; $nonMs = 0
    $hdrName = ''; if ($rows.Count -gt 0) { $hdrName = $rows[0].c1 }
    foreach ($t in $rows) {
        # The header line is repeated for every task folder; it is always the
        # first line, so any row equal to it is a header (in any language).
        if ((Nz $t.c1) -eq '' -or $t.c1 -eq $hdrName) { continue }
        $key = $t.c1 + '|' + $t.c8
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = 1; $count++
        Row $f @($t.c1, $t.c3, $t.c14, $t.c7, $t.c8, $t.c2)
        $ms = (Lc $t.c1).StartsWith('\microsoft\')
        if (-not $ms) { $nonMs++ }
        $s = Test-Susp $t.c8
        if ($s -eq 'strong') { Flag HIGH $t.c1 ("task runs a suspicious command: {0}" -f $t.c8) }
        elseif ($s -eq 'weak') { Flag HIGH $t.c1 ("task runs a program from an unusual folder: {0}" -f $t.c8) }
        elseif (-not $ms) {
            $ln = Lc ([IO.Path]::GetFileName((Get-ExePath $t.c8)))
            if ($ShellNames -contains $ln) { Flag MED $t.c1 ("task outside \Microsoft\ runs {0} as {1}: {2}" -f $ln, $t.c14, $t.c8) }
            else { Flag LOW $t.c1 ("task outside \Microsoft\ as {0}: {1}" -f $t.c14, $t.c8) }
        }
    }
    if ($rows.Count -eq 0 -and -not $Replay) { Note 'schtasks returned nothing' }
    Say ('Scheduled tasks: {0} ({1} outside \Microsoft\)' -f $count, $nonMs)
}

function S-security {
    $f = NewCsv security @('setting', 'value', 'good', 'note')
    $dc = IsDC; $build = Build
    # Chk name value good bad-severity note: record, flag when not good.
    function Chk([string]$name, $value, [bool]$ok, [string]$sev, [string]$why) {
        $v = $value; if ($null -eq $v) { $v = '(not set)' }
        Row $f @($name, $v, $ok, $why)
        if (-not $ok -and $sev) { Flag $sev $name ("{0} = {1}: {2}" -f $name, $v, $why) }
    }
    $wd = Reg "$CCS\Control\SecurityProviders\WDigest" 'UseLogonCredential'
    Chk 'WDigest UseLogonCredential' $wd ($wd -ne '1') HIGH 'passwords are kept in memory in clear text'
    $lua = Reg "$CV\Policies\System" 'EnableLUA'
    Chk 'UAC EnableLUA' $lua ($lua -ne '0') HIGH 'UAC is off: every admin program runs fully elevated'
    $latfp = Reg "$CV\Policies\System" 'LocalAccountTokenFilterPolicy'
    Chk 'LocalAccountTokenFilterPolicy' $latfp ($latfp -ne '1') MED 'local admin accounts get full rights over the network (pass-the-hash)'
    $ppl = Reg "$CCS\Control\Lsa" 'RunAsPPL'
    Chk 'LSA protection (RunAsPPL)' $ppl ($ppl -eq '1' -or $ppl -eq '2') LOW 'lsass is not protected from memory reads'
    $lm = Reg "$CCS\Control\Lsa" 'LmCompatibilityLevel'
    $lmv = 3; if ($null -ne $lm) { [void][int]::TryParse($lm, [ref]$lmv) }
    Chk 'LmCompatibilityLevel' $lm ($lmv -ge 3) MED 'LM or NTLMv1 answers are sent (easy to crack)'
    $nolm = Reg "$CCS\Control\Lsa" 'NoLMHash'
    Chk 'NoLMHash' $nolm ($nolm -ne '0') MED 'LM password hashes are stored'
    $eia = Reg "$CCS\Control\Lsa" 'EveryoneIncludesAnonymous'
    Chk 'EveryoneIncludesAnonymous' $eia ($eia -ne '1') HIGH 'anonymous users get everything Everyone has'
    $ra = Reg "$CCS\Control\Lsa" 'RestrictAnonymous'; $ras = Reg "$CCS\Control\Lsa" 'RestrictAnonymousSAM'
    Chk 'RestrictAnonymousSAM' $ras ($ras -ne '0') MED 'anonymous users can list accounts and shares'
    Row $f @('RestrictAnonymous', (Nz $ra), $true, 'recorded')
    $rnsa = Reg "$CCS\Services\LanmanServer\Parameters" 'RestrictNullSessAccess'
    Chk 'RestrictNullSessAccess' $rnsa ($rnsa -ne '0') HIGH 'null sessions can reach shares and pipes'
    $nss = Reg "$CCS\Services\LanmanServer\Parameters" 'NullSessionShares'
    Chk 'NullSessionShares' $nss ((Nz $nss).Trim() -eq '') MED 'these shares are open to anonymous users'

    # SMBv1: the server setting, or the default for this Windows version
    # (on by default before Windows 10 1709 / Server 2019).
    $smb = @(Get-Rows -Name smb_server -Props @('EnableSMB1Protocol', 'RequireSecuritySignature', 'EncryptData') -Command {
        if (Test-CcCommand 'Get-SmbServerConfiguration') { Get-SmbServerConfiguration }  # ps2-ok
    })
    $smb1 = Reg "$CCS\Services\LanmanServer\Parameters" 'SMB1'
    if ($smb.Count -gt 0) { $on = ($smb[0].EnableSMB1Protocol -eq 'True'); $src = 'Get-SmbServerConfiguration' }  # ps2-ok (text, not a call)
    elseif ($null -ne $smb1) { $on = ($smb1 -ne '0'); $src = 'registry' }
    else { $on = ($build -gt 0 -and $build -lt 16299); $src = 'default for build ' + $build }
    Chk 'SMBv1 server' ('{0} ({1})' -f $on, $src) (-not $on) MED 'SMBv1 is on (EternalBlue and relay attacks); turn it off unless something scored needs it'
    $mrx = Reg "$CCS\Services\mrxsmb10" 'Start'
    if ($null -ne $mrx) { Chk 'SMBv1 client (mrxsmb10 Start)' $mrx ($mrx -eq '4') LOW 'the SMBv1 client driver is enabled' }
    $sign = Reg "$CCS\Services\LanmanServer\Parameters" 'RequireSecuritySignature'
    if ($smb.Count -gt 0) { $sign = @{ 'True' = '1'; 'False' = '0' }[(Nz $smb[0].RequireSecuritySignature)] }
    $sev = 'LOW'; if ($dc) { $sev = 'MED' }
    Chk 'SMB server signing required' $sign ($sign -eq '1' -or ($dc -and $null -eq $sign)) $sev 'SMB relay attacks are possible'

    # RDP.
    $deny = Reg "$CCS\Control\Terminal Server" 'fDenyTSConnections'
    $rdpOn = ($deny -eq '0')
    Row $f @('RDP enabled', $rdpOn, $true, 'recorded')
    if ($rdpOn) {
        $nla = Reg "$CCS\Control\Terminal Server\WinStations\RDP-Tcp" 'UserAuthentication'
        Chk 'RDP Network Level Authentication' $nla ($nla -ne '0') MED 'RDP shows the logon screen before authenticating (brute force, BlueKeep-style bugs)'
        $port = Reg "$CCS\Control\Terminal Server\WinStations\RDP-Tcp" 'PortNumber'
        if ($port -and $port -ne '3389') { Flag LOW 'RDP port' "RDP listens on $port, not 3389" }
        Say 'RDP: on'
    }

    $aie = Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
    $aieU = @(RegRows 'HKU' -Under | Where-Object { $_.Name -eq 'AlwaysInstallElevated' -and $_.Value -eq '1' })
    Chk 'AlwaysInstallElevated' $aie (-not ($aie -eq '1' -and $aieU.Count -gt 0)) HIGH 'any user can install an MSI as SYSTEM'
    $llmnr = Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast'
    Chk 'LLMNR off (EnableMulticast)' $llmnr ($llmnr -eq '0') LOW 'LLMNR answers can be spoofed to capture hashes'
    $sbl = Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
    Chk 'PowerShell script block logging' $sbl ($sbl -eq '1') LOW 'PowerShell commands are not logged'

    # Stored logon password (the value itself is never read into the output).
    $aal = Reg "$NT\Winlogon" 'AutoAdminLogon'; $dp = Reg "$NT\Winlogon" 'DefaultPassword'
    Chk 'Winlogon stored password' $(if ($dp) { 'present' } else { 'none' }) (-not $dp) HIGH ('a logon password is stored in the registry in clear text (AutoAdminLogon=' + (Nz $aal) + ', user ' + (Nz (Reg "$NT\Winlogon" 'DefaultUserName')) + ')')

    # Port forwards (netsh interface portproxy) relay traffic through this box.
    foreach ($r in @(RegRows "$CCS\Services\PortProxy" -Under)) {
        Row $f @('portproxy ' + (($r.Key -split '\\')[-2..-1] -join '/'), ($r.Name + ' -> ' + $r.Value), $false, 'port forward')
        Flag HIGH ('portproxy ' + $r.Name) ("this box forwards {0} to {1}" -f $r.Name, $r.Value)
    }

    # Zerologon (CVE-2020-1472) on domain controllers.
    if ($dc) {
        $fscp = Reg "$CCS\Services\Netlogon\Parameters" 'FullSecureChannelProtection'
        $vca = Reg "$CCS\Services\Netlogon\Parameters" 'vulnerable_channel_allowlist'
        if ($fscp -eq '0') { Chk 'Zerologon FullSecureChannelProtection' $fscp $false HIGH 'enforcement turned off: Zerologon works against this DC' }
        else { Chk 'Zerologon FullSecureChannelProtection' $fscp ($fscp -eq '1') LOW 'not set: protected only if updates from August 2020 on are installed (see updates)' }
        if ($null -ne $vca) { Chk 'Zerologon vulnerable_channel_allowlist' 'present' $false HIGH 'some machines are allowed the vulnerable Netlogon channel' }
    }

    # Audit policy: all "No Auditing" means someone cleared it.
    $ap = @(Get-Text -Name auditpol -Command { auditpol /get /category:* })
    $sub = @($ap | Where-Object { $_ -match '^\s{2,}\S.*\s{2,}(Success|Failure|No Auditing)' })
    $none = @($sub | Where-Object { $_ -match 'No Auditing\s*$' })
    if ($sub.Count -gt 0) {
        Chk 'audit policy' ('{0} of {1} subcategories not audited' -f $none.Count, $sub.Count) ($none.Count -lt $sub.Count) MED 'nothing is audited: the policy was probably cleared'
        $logon = @($sub | Where-Object { $_ -match '^\s+Logon\s{2,}' -and $_ -match 'No Auditing' })
        if ($logon.Count -gt 0) { Flag MED 'audit Logon' 'logons are not audited' }
    } elseif (-not $Replay -or $ap.Count -gt 0) { Note 'audit policy not read (needs admin; English names only)' }
}

function S-firewall {
    $f = NewCsv firewall_profiles @('profile', 'state', 'inbound', 'outbound')
    $lines = @(Get-Text -Name fw_profiles -Command { netsh advfirewall show allprofiles })
    $prof = ''; $st = @{}
    $found = 0
    foreach ($l in $lines) {
        if ($l -match '^(\S+) Profile Settings') { $prof = $matches[1]; $st[$prof] = @{ state = ''; pol = '' }; continue }
        if (-not $prof) { continue }
        if ($l -match '^State\s+(\S+)') { $st[$prof].state = $matches[1] }
        if ($l -match '^Firewall Policy\s+(\S+)') { $st[$prof].pol = $matches[1] }
    }
    foreach ($p in @('Domain', 'Private', 'Public')) {
        if (-not $st.ContainsKey($p)) { continue }
        $found++
        $pol = @($st[$p].pol -split ',')
        $in = $pol[0]; $out = ''; if ($pol.Count -gt 1) { $out = $pol[1] }
        Row $f @($p, $st[$p].state, $in, $out)
        if ($st[$p].state -eq 'OFF') { Flag HIGH "firewall $p" "the $p firewall profile is OFF" }
        if ($in -eq 'AllowInbound') { Flag HIGH "firewall $p" "the $p profile allows all inbound traffic by default" }
    }
    if ($found -eq 0) { Note 'firewall profiles not read (English netsh output expected)' }
    else { Say ('Firewall: ' + ((@('Domain', 'Private', 'Public') | Where-Object { $st.ContainsKey($_) } | ForEach-Object { $_ + ' ' + $st[$_].state }) -join ', ')) }

    # Inbound allow rules.  "verbose" adds the program.
    $r = NewCsv firewall_rules @('name', 'enabled', 'direction', 'action', 'profiles', 'protocol', 'local_port', 'remote_ip', 'program')
    $rules = @(); $cur = $null
    foreach ($l in @(Get-Text -Name fw_rules -Command { netsh advfirewall firewall show rule name=all dir=in verbose })) {
        if ($l -match '^Rule Name:\s*(.*)$') { if ($cur) { $rules += $cur }; $cur = @{ name = $matches[1].Trim() }; continue }
        if ($cur -and $l -match '^([A-Za-z ]+):\s*(.*)$') { $cur[$matches[1].Trim()] = $matches[2].Trim() }
    }
    if ($cur) { $rules += $cur }
    $allow = 0
    foreach ($x in $rules) {
        if ($x['Direction'] -ne 'In' -or $x['Action'] -ne 'Allow') { continue }
        Row $r @($x.name, $x['Enabled'], $x['Direction'], $x['Action'], $x['Profiles'], $x['Protocol'], $x['LocalPort'], $x['RemoteIP'], $x['Program'])
        if ($x['Enabled'] -ne 'Yes') { continue }
        $allow++
        $prog = Nz $x['Program']; $lp = Nz $x['LocalPort']; $proto = Nz $x['Protocol']
        if (($proto -eq 'Any') -and ($lp -eq 'Any' -or $lp -eq '') -and ($prog -eq '' -or $prog -eq 'Any') -and ((Nz $x['RemoteIP']) -eq 'Any') -and ((Nz $x['Service']) -eq '' -or (Nz $x['Service']) -eq 'Any')) {
            Flag HIGH $x.name 'enabled inbound rule allows every port, protocol and address'
        } elseif ((Test-Susp $prog) -ne '' -or $ShellNames -contains (Lc ([IO.Path]::GetFileName($prog))) -or $NetToolNames -contains (Lc ([IO.Path]::GetFileName($prog)))) {
            Flag HIGH $x.name "inbound allow rule for an unusual program: $prog"
        } else {
            $ports = @($lp -split ',' | ForEach-Object { $_.Trim() })
            foreach ($bp in $BadPorts) { if ($ports -contains [string]$bp) { Flag HIGH $x.name "inbound allow rule opens backdoor port $bp" } }
        }
    }
    if ($rules.Count -gt 0) { Say ('Firewall inbound allow rules enabled: ' + $allow) }
}

function S-defender {
    $f = NewCsv defender @('setting', 'value')
    $st = @(Get-Rows -Name defender_status -Props @('AMServiceEnabled', 'AntivirusEnabled', 'RealTimeProtectionEnabled', 'BehaviorMonitorEnabled', 'IsTamperProtected', 'AntivirusSignatureLastUpdated') -Command {
        if (Test-CcCommand 'Get-MpComputerStatus') { Get-MpComputerStatus }  # ps2-ok
    })
    $pr = @(Get-Rows -Name defender_prefs -Props @('DisableRealtimeMonitoring', @{Name = 'ExclusionPath'; Expression = { (@($_.ExclusionPath) -join '|') } }, @{Name = 'ExclusionProcess'; Expression = { (@($_.ExclusionProcess) -join '|') } }, @{Name = 'ExclusionExtension'; Expression = { (@($_.ExclusionExtension) -join '|') } }) -Command {
        if (Test-CcCommand 'Get-MpPreference') { Get-MpPreference }  # ps2-ok
    })
    if ($st.Count -gt 0) {
        $s = $st[0]
        foreach ($n in @('AMServiceEnabled', 'AntivirusEnabled', 'RealTimeProtectionEnabled', 'BehaviorMonitorEnabled', 'IsTamperProtected', 'AntivirusSignatureLastUpdated')) { Row $f @($n, $s.$n) }
        if ($s.AntivirusEnabled -eq 'False') { Flag HIGH 'Defender' 'antivirus is off (fine only if another antivirus product is installed)' }
        if ($s.RealTimeProtectionEnabled -eq 'False') { Flag HIGH 'Defender' 'real-time protection is off' }
        Say ('Defender: antivirus {0}, real-time {1}, tamper protection {2}' -f $s.AntivirusEnabled, $s.RealTimeProtectionEnabled, $s.IsTamperProtected)
    }
    # Policy and direct settings that turn it off.
    foreach ($k in @('HKLM\SOFTWARE\Policies\Microsoft\Windows Defender', 'HKLM\SOFTWARE\Microsoft\Windows Defender')) {
        foreach ($n in @('DisableAntiSpyware', 'DisableAntiVirus')) { $v = Reg $k $n; if ($v -eq '1') { Row $f @("$k\$n", $v); Flag HIGH 'Defender' "$n = 1 in $k" } }
        foreach ($n in @('DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableOnAccessProtection')) { $v = Reg ($k + '\Real-Time Protection') $n; if ($v -eq '1') { Row $f @("$k\Real-Time Protection\$n", $v); Flag HIGH 'Defender' "$n = 1" } }
    }
    # Exclusions: things Defender will never scan.
    $ex = @()
    foreach ($r in @(RegRows 'HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions' -Under) + @(RegRows 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions' -Under)) {
        $ex += ((($r.Key -split '\\')[-1]) + '|' + $r.Name)
    }
    if ($pr.Count -gt 0) {
        foreach ($t in @(@('Path', 'Paths'), @('Process', 'Processes'), @('Extension', 'Extensions'))) {
            foreach ($v in @((Nz $pr[0].('Exclusion' + $t[0])) -split '\|')) { if ($v -ne '' -and $v -notmatch '^N/A') { $ex += ($t[1] + '|' + $v) } }
        }
    }
    foreach ($e in @($ex | Select-Object -Unique)) {
        $kind, $val = $e -split '\|', 2
        Row $f @("exclusion ($kind)", $val)
        $lv = Lc $val
        if ($lv -match '^[a-z]:\\?$' -or $lv -match '^\.?(exe|dll|ps1|bat|cmd|vbs|js|hta|scr)$' -or (Test-Susp $val) -ne '' -or $lv -match '\\(users|windows\\temp|programdata)\\?$') {
            Flag HIGH "exclusion $val" "Defender skips $kind '$val': a place to hide tools"
        } else {
            Flag MED "exclusion $val" "Defender skips $kind '$val': check a product you run needs it"
        }
    }
    if ($st.Count -eq 0 -and $pr.Count -eq 0 -and -not $Replay) { Note 'Defender cmdlets not present (older Windows): registry only' }
}

function S-processes {
    $f = NewCsv processes @('pid', 'ppid', 'name', 'program', 'owner', 'started', 'command_line')
    $procs = @(Get-Procs)
    $byPid = @{}; foreach ($p in $procs) { $byPid[[string]$p.ProcessId] = $p }
    $sysNames = @{ 'svchost.exe' = 'system32'; 'lsass.exe' = 'system32'; 'csrss.exe' = 'system32'; 'winlogon.exe' = 'system32'; 'services.exe' = 'system32'; 'smss.exe' = 'system32'; 'wininit.exe' = 'system32'; 'lsm.exe' = 'system32'; 'spoolsv.exe' = 'system32'; 'taskhostw.exe' = 'system32'; 'taskhost.exe' = 'system32'; 'explorer.exe' = 'windows' }
    $lsass = 0
    foreach ($p in $procs) {
        Row $f @($p.ProcessId, $p.ParentProcessId, $p.Name, $p.ExecutablePath, $p.Owner, (WDate (Nz $p.CreationDate)), $p.CommandLine)
        $ln = Lc $p.Name; $exe = Lc $p.ExecutablePath
        $item = ('{0} ({1})' -f $p.Name, $p.ProcessId)
        if ($ln -eq 'lsass.exe') { $lsass++ }
        if ($sysNames.ContainsKey($ln) -and $exe -ne '') {
            $okDir = '^[a-z]:\\windows\\(system32|syswow64)\\$'
            if ($sysNames[$ln] -eq 'windows') { $okDir = '^[a-z]:\\windows\\(syswow64\\)?$' }
            $dir = $exe.Substring(0, $exe.LastIndexOf('\') + 1)
            if ($dir -notmatch $okDir) { Flag HIGH $item ("system program name running from the wrong folder: {0}" -f $p.ExecutablePath) }
        }
        $s = Test-Susp $p.CommandLine
        if ($NetToolNames -contains $ln) { Flag HIGH $item ("netcat-style tool running: {0}" -f $p.CommandLine) }
        elseif ($s -eq 'strong') { Flag HIGH $item ("suspicious command line: {0}" -f $p.CommandLine) }
        elseif ((Test-Susp $p.ExecutablePath) -eq 'weak') { Flag MED $item ("runs from an unusual folder: {0}" -f $p.ExecutablePath) }
        if ($ShellNames -contains $ln) {
            $par = $byPid[[string]$p.ParentProcessId]
            if ($par -and $ServerParents -contains (Lc $par.Name)) { Flag HIGH $item ("{0} was started by {1}: a web shell or database command execution" -f $p.Name, $par.Name) }
        }
    }
    if ($lsass -gt 1) { Flag HIGH 'lsass.exe' "$lsass processes named lsass.exe (there is only ever one)" }
    if ($procs.Count -gt 0 -and -not $Replay -and -not $IsAdmin) { Note 'not elevated: paths and owners of system processes missing' }
    Say ('Processes: ' + $procs.Count)
}

function S-connections {
    $f = NewCsv connections @('proto', 'local', 'remote', 'state', 'pid', 'process', 'program')
    $n = 0
    foreach ($s in @(Get-Sockets | Where-Object { -not $_.Listen })) {
        $p = Proc $s.Pid
        $name = ''; $exe = ''
        if ($p) { $name = Nz $p.Name; $exe = Nz $p.ExecutablePath }
        Row $f @($s.Proto, ($s.LAddr + ':' + $s.LPort), ($s.RAddr + ':' + $s.RPort), $s.State, $s.Pid, $name, $exe)
        if ($s.RAddr -eq '127.0.0.1' -or $s.RAddr -eq '::1') { continue }
        if ($s.State -ne 'ESTABLISHED') { continue }
        $n++
        $item = ('{0} -> {1}:{2}' -f $name, $s.RAddr, $s.RPort)
        $rp = 0; [void][int]::TryParse($s.RPort, [ref]$rp)
        $ln = Lc $name
        if ($ShellNames -contains $ln -or $NetToolNames -contains $ln) { Flag HIGH $item ("{0} has a live connection to {1}:{2} (reverse shell?)" -f $name, $s.RAddr, $s.RPort) }
        elseif ($BadPorts -contains $rp) { Flag HIGH $item "connection to common backdoor port $rp" }
        elseif ((Test-Susp $exe) -ne '') { Flag MED $item "program in an unusual folder has a live connection: $exe" }
    }
    Say ('Established connections: ' + $n)
}

function S-sessions {
    $f = NewCsv sessions @('kind', 'user', 'from', 'detail')
    foreach ($l in @(Get-Text -Name query_user -Command { if (Test-Path -LiteralPath (Join-Path $env:SystemRoot 'System32\quser.exe')) { quser } })) {
        $t = $l.Trim().TrimStart('>')
        if ($t -eq '' -or $t -match '^USERNAME' -or $t.StartsWith('ERROR') -or $t -match 'No User exists') { continue }
        $parts = @($t -split '\s{2,}')
        Row $f @('logon', $parts[0], '', ($parts[1..($parts.Count - 1)] -join ' | '))
    }
    foreach ($l in @(Get-Text -Name net_session -Command { net session })) {
        if ($l -match '^\\\\(\S+)\s+(\S+)?') { Row $f @('smb session', $matches[2], $matches[1], $l.Trim()) }
    }
}

function S-shares {
    $f = NewCsv shares @('name', 'path', 'type', 'description', 'access')
    $acl = @(Get-Rows -Name share_acl -Props @('Share', 'Trustee', 'Access') -Command {
        foreach ($s in @(Get-Wmi Win32_LogicalShareSecuritySetting)) {
            try {
                $sd = $s.GetSecurityDescriptor().Descriptor
                foreach ($a in @($sd.DACL)) {
                    $who = $a.Trustee.Name; if ($a.Trustee.Domain) { $who = $a.Trustee.Domain + '\' + $who }
                    $m = [int64]$a.AccessMask
                    $acc = 'Read'; if (($m -band 0x1F01FF) -eq 0x1F01FF) { $acc = 'Full' } elseif (($m -band 0x1301BF) -eq 0x1301BF) { $acc = 'Change' }
                    if ($a.AceType -eq 1) { $acc = 'Deny ' + $acc }
                    New-Object PSObject -Property @{ Share = $s.Name; Trustee = $who; Access = $acc }
                }
            } catch { }
        }
    })
    $defaults = @('admin$', 'ipc$', 'print$', 'netlogon', 'sysvol')
    $names = @()
    foreach ($s in @(Get-Rows -Name shares -Props @('Name', 'Path', 'Type', 'Description') -Command { Get-Wmi Win32_Share })) {
        $a = @($acl | Where-Object { $_.Share -eq $s.Name } | ForEach-Object { $_.Trustee + ':' + $_.Access })
        Row $f @($s.Name, $s.Path, $s.Type, $s.Description, ($a -join '; '))
        $ln = Lc $s.Name
        if ($defaults -contains $ln -or $ln -match '^[a-z]\$$') { continue }
        $names += $s.Name
        Flag LOW $s.Name ("shared folder {0}" -f $s.Path)
        foreach ($x in @($acl | Where-Object { $_.Share -eq $s.Name })) {
            if ((Lc $x.Trustee) -match '(^|\\)(everyone|anonymous logon|guest|guests)$' -and ($x.Access -eq 'Full' -or $x.Access -eq 'Change')) {
                Flag MED $s.Name ("{0} has {1} access to share {2}" -f $x.Trustee, $x.Access, $s.Name)
            }
        }
    }
    if ($names.Count -gt 0) { Say ('Shares: ' + ($names -join ', ')) }
}

function S-software {
    $f = NewCsv software @('name', 'version', 'publisher', 'installed')
    $rows = @(Get-Rows -Name software -Props @('DisplayName', 'DisplayVersion', 'Publisher', 'InstallDate') -Command {
        foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
            if (Test-Path -LiteralPath $root) {
                foreach ($k in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
                    $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue
                    if ($p -and $p.DisplayName) { $p }
                }
            }
        }
    })
    $remote = '(teamviewer|anydesk|screenconnect|connectwise|splashtop|rustdesk|ngrok|radmin|ultravnc|tightvnc|realvnc|tigervnc|logmein|atera|ammyy|remote ?utilities|meshagent|zoho assist|getscreen|supremo|dwservice|action1|netsupport)'
    $seen = @{}
    foreach ($s in $rows) {
        $k = Lc $s.DisplayName; if ($seen.ContainsKey($k)) { continue }; $seen[$k] = 1
        Row $f @($s.DisplayName, $s.DisplayVersion, $s.Publisher, $s.InstallDate)
        if ($k -match $remote) { Flag MED $s.DisplayName 'remote-access tool installed: check it belongs here' }
    }
    Say ('Installed programs: ' + $seen.Count)
}

function S-updates {
    $f = NewCsv updates @('id', 'description', 'installed_on', 'installed_by')
    $newest = [DateTime]::MinValue
    $rows = @(Get-Rows -Name hotfixes -Props @('HotFixID', 'Description', 'InstalledOn', 'InstalledBy') -Command { Get-Wmi Win32_QuickFixEngineering })
    foreach ($h in $rows) {
        Row $f @($h.HotFixID, $h.Description, $h.InstalledOn, $h.InstalledBy)
        $d = [DateTime]::MinValue
        # Written in this machine's date format; replayed data may come from
        # another, so the invariant (US) format is tried too.
        $ok = [DateTime]::TryParse((Nz $h.InstalledOn), [ref]$d)
        if (-not $ok) { $ok = [DateTime]::TryParse((Nz $h.InstalledOn), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$d) }
        if ($ok -and $d -gt $newest) { $newest = $d }
    }
    if ($newest -eq [DateTime]::MinValue) {
        if ($rows.Count -gt 0) { Note 'no install dates' }
        Say ('Updates: {0} installed' -f $rows.Count)
        return
    }
    $age = ([DateTime]::Now - $newest).Days
    Say ('Updates: {0} installed, newest {1:yyyy-MM-dd} ({2} days ago)' -f $rows.Count, $newest, $age)
    if ((IsDC) -and $newest -lt (Get-Date -Year 2020 -Month 9 -Day 1)) { Flag HIGH 'updates' ("newest update is from {0:yyyy-MM-dd}: this DC is probably open to Zerologon" -f $newest) }
    elseif ($age -gt 365) { Flag MED 'updates' ("newest update is {0} days old: expect known exploits to work" -f $age) }
}

function S-events {
    $f = NewCsv events @('time', 'log', 'id', 'what', 'detail')
    $what = @{ '1102' = 'Security log cleared'; '104' = 'event log cleared'; '4720' = 'account created'; '4722' = 'account enabled'; '4724' = 'password reset by someone else'; '4728' = 'added to a global group'; '4732' = 'added to a local group'; '4756' = 'added to a universal group'; '4697' = 'service installed'; '7045' = 'service installed'; '4698' = 'scheduled task created'; '7040' = 'service start type changed' }
    $since = [DateTime]::Now.AddHours(-$EventHours)
    $rows = @(Get-Rows -Name events -Props @('Time', 'Log', 'Id', 'Detail') -Command {
        $q = @(@{ LogName = 'Security'; Id = @(1102, 4720, 4722, 4724, 4728, 4732, 4756, 4697, 4698) }, @{ LogName = 'System'; Id = @(104, 7045, 7040) })
        foreach ($h in $q) {
            $h.StartTime = $since
            $ev = @()
            try { $ev = @(Get-WinEvent -FilterHashtable $h -ErrorAction Stop) } catch { if ($_.Exception.Message -notmatch 'No events') { Note ("{0} log not read: {1}" -f $h.LogName, $_.Exception.Message) } }
            foreach ($e in $ev) {
                # Names only: account, group and service names from the message.
                $m = Nz $e.Message
                $names = @([regex]::Matches($m, '(Account Name|Group Name|Service Name|Task Name|Service File Name):\s*([^\r\n]+)') | ForEach-Object { $_.Groups[1].Value + '=' + $_.Groups[2].Value.Trim() })
                if ($names.Count -eq 0) { $names = @(($m -split "`n")[0]) }
                New-Object PSObject -Property @{ Time = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); Log = $h.LogName; Id = $e.Id; Detail = ($names -join '; ') }
            }
        }
    })
    $counts = @{}
    foreach ($e in $rows) {
        $id = [string]$e.Id
        $w = $what[$id]; if (-not $w) { $w = 'event ' + $id }
        Row $f @($e.Time, $e.Log, $id, $w, $e.Detail)
        $counts[$w] = 1 + [int]$counts[$w]
        $item = ('{0} {1}' -f $e.Time, $w)
        if ($id -eq '1102' -or $id -eq '104') { Flag HIGH $item ("{0} at {1}: someone hid their tracks" -f $w, $e.Time) }
        elseif ($id -eq '7040') { if ((Lc $e.Detail) -match '(windefend|eventlog|mpssvc|wscsvc)') { Flag MED $item $e.Detail } }
        else { Flag MED $item ('{0}: {1}' -f $w, $e.Detail) }
    }
    if ($rows.Count -gt 0) { Say (('Events in the last {0}h: ' -f $EventHours) + (($counts.Keys | ForEach-Object { '{0} x{1}' -f $_, $counts[$_] }) -join ', ')) }
    if (-not $Replay -and -not $IsAdmin) { Note 'not elevated: Security log not read' }
}

function S-drivers {
    $f = NewCsv drivers @('name', 'display_name', 'state', 'start_mode', 'path')
    foreach ($d in @(Get-Rows -Name drivers -Props @('Name', 'DisplayName', 'State', 'StartMode', 'PathName') -Command { Get-Wmi Win32_SystemDriver })) {
        Row $f @($d.Name, $d.DisplayName, $d.State, $d.StartMode, $d.PathName)
        if ($d.State -ne 'Running') { continue }
        $p = Lc $d.PathName
        if ($p -eq '') { continue }
        if ((Test-Susp $p) -ne '') { Flag HIGH $d.Name ("driver loaded from an unusual folder: {0}" -f $d.PathName) }
        elseif ($p -notmatch '\\windows\\' -and $p -notmatch '^\\systemroot\\' -and $p -notmatch '^system32\\') { Flag MED $d.Name ("driver loaded from outside Windows: {0}" -f $d.PathName) }
    }
}

function S-rights {
    $f = NewCsv rights @('right', 'holders')
    $lines = @(Get-Text -Name user_rights -Command {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ('cc_rights_' + $PID + '.inf')
        $null = secedit /export /cfg $tmp /areas USER_RIGHTS /quiet
        if (Test-Path -LiteralPath $tmp) { Get-Content -LiteralPath $tmp; Remove-Item -LiteralPath $tmp -Force }
    })
    # Who may hold the powerful rights by default: Administrators, Backup
    # Operators, SYSTEM, LOCAL SERVICE, NETWORK SERVICE, SERVICE, IIS_IUSRS,
    # Server Operators, per-service accounts (S-1-5-80-*), app pools (S-1-5-82-*).
    $okSid = '^\*?(S-1-5-32-544|S-1-5-32-551|S-1-5-32-549|S-1-5-18|S-1-5-19|S-1-5-20|S-1-5-6|S-1-5-32-568|S-1-5-80-[0-9-]+|S-1-5-82-[0-9-]+|S-1-5-83-0|S-1-5-90-0)$'
    $powerful = @('SeDebugPrivilege', 'SeImpersonatePrivilege', 'SeAssignPrimaryTokenPrivilege', 'SeTcbPrivilege', 'SeCreateTokenPrivilege', 'SeLoadDriverPrivilege', 'SeTakeOwnershipPrivilege', 'SeBackupPrivilege', 'SeRestorePrivilege', 'SeTrustedCredManAccessPrivilege')
    $n = 0
    foreach ($l in $lines) {
        if ($l -notmatch '^(Se\w+)\s*=\s*(.*)$') { continue }
        $right = $matches[1]; $who = @($matches[2] -split ',' | ForEach-Object { $_.Trim() })
        Row $f @($right, ($who -join ', ')); $n++
        if ($powerful -contains $right) {
            foreach ($w in $who) { if ($w -notmatch $okSid) { Flag MED "$right $w" ("{0} holds {1} (can become SYSTEM or read any file)" -f $w, $right) } }
        }
        if ($right -eq 'SeInteractiveLogonRight' -or $right -eq 'SeRemoteInteractiveLogonRight' -or $right -eq 'SeNetworkLogonRight') {
            foreach ($w in $who) { if ($w -match '^\*?(S-1-5-7|S-1-5-32-546)$' -or ($w -match '^\*?S-1-1-0$' -and $right -ne 'SeNetworkLogonRight')) { Flag HIGH "$right $w" ("{0} given to {1}" -f $right, $w) } }
        }
    }
    if ($n -eq 0 -and -not $Replay) { Note 'user rights not read (needs admin)' }
}

function S-roles {
    $f = NewCsv roles @('kind', 'name')
    $feat = @(Get-Rows -Name features -Props @('ID', 'Name') -Command { if (IsServer) { Get-Wmi Win32_ServerFeature } })
    foreach ($x in $feat) { Row $f @('feature', $x.Name) }
    $key = @{ 'ntds' = 'Domain controller'; 'dns' = 'DNS server'; 'dhcpserver' = 'DHCP server'; 'w3svc' = 'IIS web'; 'ftpsvc' = 'IIS FTP'; 'smtpsvc' = 'SMTP'; 'certsvc' = 'Certificate Services'; 'mssqlserver' = 'SQL Server'; 'mysql' = 'MySQL'; 'msexchangeis' = 'Exchange'; 'termservice' = 'Remote Desktop'; 'winrm' = 'WinRM'; 'sshd' = 'OpenSSH server'; 'apache2.4' = 'Apache'; 'tomcat9' = 'Tomcat'; 'nfsservice' = 'NFS server'; 'wsusservice' = 'WSUS' }
    $have = @()
    # Most telling first.
    $order = @('Domain controller', 'DNS server', 'DHCP server', 'Certificate Services', 'Exchange', 'IIS web', 'IIS FTP', 'SQL Server', 'MySQL', 'Apache', 'Tomcat', 'SMTP', 'WSUS', 'NFS server', 'OpenSSH server', 'Remote Desktop', 'WinRM')
    foreach ($s in @(Get-Services)) {
        $ln = Lc $s.Name
        if ($key.ContainsKey($ln) -and $s.State -eq 'Running') { $have += $key[$ln]; Row $f @('service', ('{0} ({1})' -f $key[$ln], $s.Name)) }
        elseif ($ln -like 'mssql$*' -and $s.State -eq 'Running') { $have += 'SQL Server'; Row $f @('service', ('SQL Server ({0})' -f $s.Name)) }
    }
    if ($have.Count -gt 0) { Say ('Runs: ' + ((@($order | Where-Object { $have -contains $_ })) -join ', ')) }
}

function S-logs {
    if ($Replay) { Note 'not copied in a replay'; return }
    $d = Join-Path $Cc.RunDir 'logs'
    New-Item -ItemType Directory -Path $d -Force | Out-Null
    $f = NewCsv logs_copied @('log', 'file', 'result')
    foreach ($l in @('Security', 'System', 'Application', 'Windows PowerShell', 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-TaskScheduler/Operational', 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational', 'Microsoft-Windows-WMI-Activity/Operational', 'Microsoft-Windows-Windows Defender/Operational')) {
        $file = Join-Path $d (($l -replace '[/ ]', '_') + '.evtx')
        $out = @(Invoke-CcProgram -FilePath 'wevtutil.exe' -Arguments @('epl', $l, $file))
        $res = 'copied'; if ($LASTEXITCODE -ne 0) { $res = 'not copied: ' + (($out -join ' ').Trim()) }
        Row $f @($l, $file, $res)
    }
    Say ('Event logs copied to ' + $d)
}

# =============================================================================
# Run the sections and write the summary
# =============================================================================
foreach ($s in $Run) {
    $script:Sec = $s; $script:SecNote = ''; $script:SecRows = 0
    $t0 = [DateTime]::UtcNow
    try {
        & ('S-' + $s)
    } catch {
        Note ('stopped early: ' + $_.Exception.Message)
        Write-CcLog -Level WARN -Message ("section {0} stopped early: {1}" -f $s, $_.Exception.Message)
    }
    $secs = ([DateTime]::UtcNow - $t0).TotalSeconds
    $script:SecTable += ('{0,-12} {1,6} rows {2,6:N1}s  {3}' -f $s, $script:SecRows, $secs, $script:SecNote)
    Write-CcLog -Level DEBUG -Message ("section {0}: {1} rows in {2:N1}s {3}" -f $s, $script:SecRows, $secs, $script:SecNote)
}

$sum = @()
$sum += ('SH-06 Windows collector  {0}  profile {1}' -f [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm 'UTC'"), $Level)
$sum += ''
$sum += $script:Facts
$sum += ''
$sum += 'Sections:'
$sum += @($script:SecTable | ForEach-Object { '  ' + $_ })
$sum += ''
$sum += @(Get-CcFlagReport -Max $MaxFlags)
$sumFile = Join-Path $Cc.RunDir 'summary.txt'
[IO.File]::WriteAllLines($sumFile, [string[]]$sum)
if (-not $Quiet) { foreach ($l in $sum) { Write-Host $l } }
Write-Host ('All results: ' + $Cc.RunDir)
Complete-Cc
