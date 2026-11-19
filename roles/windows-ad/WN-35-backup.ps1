# =============================================================================
# ID:       WN-35
# NAME:     Windows backup
# ROLE:     Windows / AD  (wave 1, first 15 minutes)
# KIND:     readonly - writes only into the output folder
# VERSION:  1.0.0
#
# PURPOSE
#   Run right after the collector (SH-06) and BEFORE any script that changes
#   the box.  It saves the settings a hardening step or the red team is most
#   likely to break, each with the command that puts it back, so a fix that
#   breaks a scored service can be undone in seconds:
#     every box      firewall rules, security policy and user rights, audit
#                    policy, scheduled tasks, hosts file, key registry areas,
#                    local users and group members (a list, not passwords)
#     when present   IIS settings and site files, DNS zones, DHCP settings;
#                    on a domain controller Group Policy, SYSVOL and a list of
#                    every user, group, computer and OU
#   It writes RESTORE.txt (what to run to put each item back), hashes every
#   saved file, and can copy the whole backup to another machine (-CopyTo),
#   because a red team with admin rights can delete a backup kept on the box.
#
# USAGE
#   powershell -NoProfile -ExecutionPolicy Bypass -File WN-35-backup.ps1 -Out C:\bt-out [options]
#   Run in an elevated window.  Without elevation most items fail and are
#   listed as failed.
#
# OPTIONS
#   -Path a,b         also back up these files or folders (application
#                     folders, config files, XAMPP ...)
#   -NoWebRoots       leave website files out (settings are still saved)
#   -MaxMB N          skip any single folder larger than N MB (default 500);
#                     it is listed as skipped, so you can add it by hand
#   -CopyTo DEST      copy the finished backup to DEST, a share or folder
#                     (\\10.0.0.5\backups).  A copy off the box survives a
#                     red team who deletes the one here
#   -AdDatabase       domain controller: also save the AD database with
#                     ntdsutil "IFM".  OFF by default: that copy holds every
#                     domain password hash.  Copy it off the box and delete it
#                     here, or do not make it at all
#   -Only a,b         run only these items (names from -List)
#   -List             list the items and exit
#   Common options (-Out, -DebugLog, -Quiet ...) come from the library.
#
# OUTPUTS  (under -Out, in WN-35_<host>_<UTC time>\)
#   items.csv         item,status,files,size_kb,detail - what was asked for
#                     and what happened
#   RESTORE.txt       the command to put back each item
#   SHA256SUMS.txt    hash of every saved file, to check a copy is intact
#   summary.txt       the same summary that is printed
#   registry\ firewall\ policy\ tasks\ files\ users\ iis\ web\ dns\ dhcp\
#   gpo\ sysvol\ ad\  the saved items
#
# WHAT IT CHANGES
#   Nothing on the host's settings.  It writes into the output folder only,
#   and limits that backup folder to Administrators and SYSTEM (icacls),
#   because registry exports and policy can hold sensitive values.  The DNS
#   zone export is written by dnscmd into %windir%\System32\dns and moved out
#   at once.  The AD Recycle Bin is NOT turned on (that cannot be undone);
#   its state is reported with the command to turn it on.
#
# DEPENDS ON
#   reg.exe, netsh, secedit, auditpol, icacls (every Windows); dnscmd (DNS
#   servers); netsh dhcp (DHCP servers); the GroupPolicy module (Backup-GPO)
#   and ADSI on domain controllers; ntdsutil for -AdDatabase.
#
# TESTED ON
#   Windows 11 (build 26200), Windows PowerShell 5.1, elevated: the eight
#   workstation items saved in 6 seconds.  PowerShell 7 on Linux with stand-in
#   programs (tests/wn35.Tests.ps1): every item's flow including IIS, DNS,
#   DHCP and DC items, RESTORE.txt, hashes, size limit, -CopyTo, failures.
#   NOT yet run on a real server or domain controller.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Local password hashes are NOT saved (the SAM is not copied); restoring
#     an account means recreating it.  The users list is for comparison.
#   - The AD lists are for comparison; to bring back a deleted user use the
#     AD Recycle Bin (turn it on early) or an authoritative restore.
#   - A big web root can take minutes; -MaxMB and -NoWebRoots keep it short.
#   - Restoring the security policy (secedit /configure) puts back EVERY
#     setting in the file.  Read RESTORE.txt before running it.
#   - A 32-bit PowerShell on 64-bit Windows sees the 32-bit registry view.
#
# DEBUGGING
#   -DebugLog          each command and its exit code
#   items.csv          why an item failed (the program's own message)
#   -Only NAME         rerun one item
# =============================================================================
param(
    [switch]$Apply, [string]$Out, [string]$Protected, [switch]$NoProtected,
    [switch]$ForceScored, [switch]$Quiet, [switch]$DebugLog,
    [string[]]$Path = @(),
    [switch]$NoWebRoots,
    [int]$MaxMB = 500,
    [string]$CopyTo = '',
    [switch]$AdDatabase,
    [string]$Only = '',
    [switch]$List,
    [switch]$Help
)

$ItemHelp = @(
    'registry     key registry areas: services, startup, Winlogon, LSA, RDP, SMB, firewall, policies',
    'firewall     all firewall rules and profiles (netsh advfirewall export)',
    'secpolicy    security policy and user rights (secedit)',
    'auditpol     audit policy (auditpol /backup)',
    'tasks        every scheduled task (the XML files)',
    'hosts        the hosts file and other files in drivers\etc',
    'users        local users and group members (list only, no passwords)',
    'services     every service: state, start mode, program, account (list)',
    'iis          IIS settings (applicationHost.config and friends)',
    'web          website files of every IIS site (unless -NoWebRoots)',
    'dns          DNS server zones (dnscmd) and settings',
    'dhcp         DHCP server settings and leases (netsh dhcp export)',
    'gpo          every Group Policy object (Backup-GPO) - domain controllers',
    'sysvol       the SYSVOL folder (logon scripts, policies) - domain controllers',
    'ad           every AD user, group, computer and OU (list) - domain controllers',
    'addb         the AD database via ntdsutil IFM - only with -AdDatabase',
    'paths        files and folders given with -Path'
)
$AllItems = @('registry', 'firewall', 'secpolicy', 'auditpol', 'tasks', 'hosts', 'users', 'services', 'iis', 'web', 'dns', 'dhcp', 'gpo', 'sysvol', 'ad', 'addb', 'paths')

if ($Help) {
    Write-Host 'WN-35 Windows backup - saves settings and files before anything is changed'
    Write-Host '  -Path a,b       also back up these files or folders'
    Write-Host '  -NoWebRoots     leave website files out'
    Write-Host '  -MaxMB N        skip any single folder bigger than N MB (default 500)'
    Write-Host '  -CopyTo DEST    copy the backup to a share or folder'
    Write-Host '  -AdDatabase     DC: also save the AD database (holds every password hash)'
    Write-Host '  -Only a,b       run only these items (-List shows them)'
    Write-Host '  -Out DIR -Quiet -DebugLog  common options'
    exit 0
}
if ($List) { foreach ($l in $ItemHelp) { Write-Host $l }; exit 0 }

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
$onlyList = @($Only -split '[,\s]+' | Where-Object { $_ -ne '' } | ForEach-Object { $_.ToLower() })
foreach ($n in $onlyList) { if (-not ($AllItems -contains $n)) { Write-Host "unknown item '$n' (see -List)"; exit 2 } }
if ($MaxMB -lt 1) { Write-Host '-MaxMB must be 1 or more'; exit 2 }
$Path = @($Path | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })

# Jp base 'a\b' -> base\a\b.  Join-Path refuses a drive that does not exist
# (C: when the tests run on Linux), and this also splits 'a\b' into parts.
function Jp([string]$a, [string]$b) { foreach ($part in @($b -split '[\\/]' | Where-Object { $_ -ne '' })) { $a = [IO.Path]::Combine($a, $part) }; return $a }

# ---- Start ------------------------------------------------------------------
Initialize-Cc -Id 'WN-35' -Name 'Windows backup' -Kind readonly -Bound $PSBoundParameters
Use-CcRunDir
$B = $Cc.RunDir
$IsAdmin = Test-CcAdmin
if (-not $IsAdmin) { Write-CcLog -Level WARN -Message 'not elevated: most items need an administrator window and will fail' }
$Win = $env:SystemRoot
if (-not $Win) { $Win = 'C:\Windows' }
$S32 = Jp $Win 'System32'
$os = Get-CcOsInfo

# Keep the backup readable by Administrators and SYSTEM only: registry and
# policy exports can hold sensitive values.
# Only when elevated: in a normal window the Administrators group is not
# active, and the folder would lock out the person who just made it.
if ($IsAdmin -or -not (Test-CcWindows)) { if (Test-CcCommand 'icacls.exe') {
    $o = @(Invoke-CcProgram -FilePath 'icacls.exe' -Arguments @($B, '/inheritance:r', '/grant:r', '*S-1-5-32-544:(OI)(CI)F', '*S-1-5-18:(OI)(CI)F'))
    if ($LASTEXITCODE -ne 0) { Write-CcLog -Level WARN -Message ('could not limit access to the backup folder: ' + ($o -join ' ')) }
} }

$ItemsCsv = New-CcCsv -Name items -Header @('item', 'status', 'files', 'size_kb', 'detail')
$script:Restore = @()
$script:Count = @{ ok = 0; failed = 0; skipped = 0 }
$script:Lines = @()

# Sub name -> <backup>\name, created.  (Not "Dir": that is an alias of Get-ChildItem.)
function Want([string]$item) { return ($onlyList.Count -eq 0 -or $onlyList -contains $item) }
function Sub([string]$name) { $d = Jp $B $name; if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }; return $d }
function Size([string]$p) {
    if (-not (Test-Path -LiteralPath $p)) { return 0 }
    $i = Get-Item -LiteralPath $p -Force
    if (-not $i.PSIsContainer) { return [int64]$i.Length }
    $sum = 0
    foreach ($f in @(Get-ChildItem -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer })) { $sum += $f.Length }
    return [int64]$sum
}
function Files([string]$p) { if (-not (Test-Path -LiteralPath $p)) { return 0 }; return @(Get-ChildItem -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer }).Count }

# Done item status where detail [restore lines]
#   status: ok | failed | skipped.  Every item ends with exactly one call.
function Done([string]$item, [string]$status, [string]$where = '', [string]$detail = '', [string[]]$restore = @()) {
    $n = 0; $kb = 0
    if ($where -and (Test-Path -LiteralPath $where)) { $n = Files $where; $kb = [int]((Size $where) / 1024) }
    Add-CcCsvRow -File $ItemsCsv -Values @($item, $status, $n, $kb, $detail)
    $script:Count[$status]++
    $mark = @{ ok = 'saved  '; failed = 'FAILED '; skipped = 'skipped' }[$status]
    $script:Lines += ('  {0} {1,-10} {2}' -f $mark, $item, $detail)
    $lvl = 'INFO'; if ($status -eq 'failed') { $lvl = 'WARN' }
    Write-CcLog -Level $lvl -Message ('{0}: {1} {2}' -f $item, $status, $detail)
    if ($status -eq 'ok' -and $restore.Count -gt 0) {
        $script:Restore += ''
        $script:Restore += ('## ' + $item)
        $script:Restore += $restore
    }
}

# Run program args -> $true when it exited 0.  Its output is kept in
# $script:LastOut for the item's detail.
function Run([string]$exe, [string[]]$a) {
    $script:LastOut = (@(Invoke-CcProgram -FilePath $exe -Arguments $a) -join ' ').Trim()
    Write-CcLog -Level DEBUG -Message ('{0} {1} -> exit {2}' -f $exe, ($a -join ' '), $LASTEXITCODE)
    return ($LASTEXITCODE -eq 0)
}
# Get-Wmi Class [Filter] -> objects (Get-CimInstance under PowerShell 7).
function Get-Wmi([string]$Class, [string]$Filter = '') {
    if (Test-CcCommand 'Get-WmiObject') {
        if ($Filter) { return Get-WmiObject -Class $Class -Filter $Filter -ErrorAction Stop }
        return Get-WmiObject -Class $Class -ErrorAction Stop
    }
    if ($Filter) { return Get-CimInstance -ClassName $Class -Filter $Filter -ErrorAction Stop }  # ps2-ok
    return Get-CimInstance -ClassName $Class -ErrorAction Stop  # ps2-ok
}
function Short([string]$s) { if ($s.Length -gt 160) { return $s.Substring(0, 157) + '...' }; return $s }
function Q([string]$p) { return '"' + $p + '"' }

# Copy-Tree src dest item -> copies a file or folder, honouring -MaxMB.
#   Returns 'ok', 'big' or an error message.
function Copy-Tree([string]$src, [string]$dest) {
    $mb = [int]((Size $src) / 1MB)
    if ($mb -gt $MaxMB) { return "big:$mb" }
    try {
        $parent = Split-Path -Parent $dest
        if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        Copy-Item -LiteralPath $src -Destination $dest -Recurse -Force -ErrorAction Stop
        return 'ok'
    } catch { return $_.Exception.Message }
}

# ---- Items ------------------------------------------------------------------

function I-registry {
    if (-not (Test-CcCommand 'reg.exe')) { Done registry skipped '' 'reg.exe not found (not Windows)'; return }
    $d = Sub 'registry'
    $keys = @(
        @('services', 'HKLM\SYSTEM\CurrentControlSet\Services'),
        @('run-hklm', 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
        @('runonce-hklm', 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'),
        @('run-wow64', 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'),
        @('policies-hklm', 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies'),
        @('policies-software', 'HKLM\SOFTWARE\Policies'),
        @('winlogon', 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'),
        @('ifeo', 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'),
        @('lsa', 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'),
        @('securityproviders', 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders'),
        @('terminal-server', 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server'),
        @('session-manager', 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager'),
        @('netsh-helpers', 'HKLM\SOFTWARE\Microsoft\NetSh'),
        @('defender', 'HKLM\SOFTWARE\Microsoft\Windows Defender'),
        @('run-current-user', 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run')
    )
    $ok = 0; $bad = @(); $restore = @('# Each line puts one registry area back as it was (it ADDS and OVERWRITES values;', '# values created after the backup stay).  Run in an elevated window.')
    foreach ($k in $keys) {
        $f = Jp $d ($k[0] + '.reg')
        if (Run 'reg.exe' @('export', $k[1], $f, '/y')) { $ok++; $restore += ('reg import ' + (Q $f) + '    # ' + $k[1]) }
        elseif ($script:LastOut -notmatch 'unable to find|was unable|cannot find') { $bad += $k[1] }
    }
    if ($ok -eq 0) { Done registry failed $d ('no key could be exported: ' + (Short $script:LastOut)); return }
    $det = "$ok areas exported"; if ($bad.Count -gt 0) { $det += '; failed: ' + ($bad -join ', ') }
    Done registry ok $d $det $restore
}

function I-firewall {
    if (-not (Test-CcCommand 'netsh.exe')) { Done firewall skipped '' 'netsh not found (not Windows)'; return }
    $d = Sub 'firewall'
    $f = Jp $d 'firewall.wfw'
    if (-not (Run 'netsh.exe' @('advfirewall', 'export', $f))) { Done firewall failed $d (Short $script:LastOut); return }
    $txt = Jp $d 'profiles.txt'
    [IO.File]::WriteAllLines($txt, [string[]]@(Invoke-CcProgram -FilePath 'netsh.exe' -Arguments @('advfirewall', 'show', 'allprofiles')))
    Done firewall ok $d 'all rules and profile settings' @('# Replaces ALL current firewall rules and profile settings with the saved ones.', ('netsh advfirewall import ' + (Q $f)))
}

function I-secpolicy {
    if (-not (Test-CcCommand 'secedit.exe')) { Done secpolicy skipped '' 'secedit not found (not Windows)'; return }
    $d = Sub 'policy'
    $f = Jp $d 'security-policy.inf'
    if (-not (Run 'secedit.exe' @('/export', '/cfg', $f, '/quiet')) -or -not (Test-Path -LiteralPath $f)) { Done secpolicy failed $d (Short $script:LastOut); return }
    $db = Jp $d 'restore.sdb'
    Done secpolicy ok $d 'password and lockout policy, user rights, security options' @(
        '# Puts back EVERY setting in the file (password policy, user rights, security options).',
        '# Read the file first; to put back only the user rights add  /areas USER_RIGHTS',
        ('secedit /configure /db ' + (Q $db) + ' /cfg ' + (Q $f) + ' /overwrite /quiet'))
}

function I-auditpol {
    if (-not (Test-CcCommand 'auditpol.exe')) { Done auditpol skipped '' 'auditpol not found (not Windows)'; return }
    $d = Sub 'policy'
    $f = Jp $d 'audit-policy.csv'
    if (-not (Run 'auditpol.exe' @('/backup', ('/file:' + $f))) -or -not (Test-Path -LiteralPath $f)) { Done auditpol failed $d (Short $script:LastOut); return }
    Done auditpol ok $f 'every audit subcategory' @(('auditpol /restore /file:' + (Q $f)))
}

function I-tasks {
    $src = Jp $S32 'Tasks'
    if (-not (Test-Path -LiteralPath $src)) { Done tasks skipped '' "$src not found"; return }
    $d = Jp $B 'tasks'
    $r = Copy-Tree $src $d
    if ($r -ne 'ok') { Done tasks failed $d (Short $r); return }
    Done tasks ok $d 'every task definition (XML)' @(
        '# Put back one task (the name is its path under tasks\, with \ separators):',
        ('schtasks /create /tn "\TaskName" /xml ' + (Q (Jp $d 'TaskName')) + ' /f'),
        '# Compare with what exists now to find tasks the red team added:',
        ('Get-ChildItem -Recurse ' + (Q $d) + ' | Where-Object { -not $_.PSIsContainer } | ForEach-Object { $_.FullName.Substring(' + ($d.Length) + ') }'))
}

function I-hosts {
    $src = Jp $S32 'drivers\etc'
    if (-not (Test-Path -LiteralPath $src)) { Done hosts skipped '' "$src not found"; return }
    $d = Jp $B 'files\etc'
    $r = Copy-Tree $src $d
    if ($r -ne 'ok') { Done hosts failed $d (Short $r); return }
    Done hosts ok $d 'hosts, networks, protocol, services' @(('Copy-Item ' + (Q (Jp $d 'hosts')) + ' ' + (Q (Jp $src 'hosts')) + ' -Force'))
}

function Test-Wmi { return ((Test-CcCommand 'Get-WmiObject') -or (Test-CcCommand 'Get-CimInstance')) }  # ps2-ok (a name, not a call)
function I-users {
    if (-not (Test-Wmi)) { Done users skipped '' 'WMI not available (not Windows)'; return }
    $d = Sub 'users'
    $u = Jp $d 'local-users.csv'; $g = Jp $d 'group-members.csv'
    $ok = $false
    try {
        $rows = @(Get-Wmi Win32_UserAccount 'LocalAccount=True' | Select-Object Name, SID, Disabled, PasswordRequired, PasswordExpires, Description)
        [IO.File]::WriteAllLines($u, [string[]]@($rows | ConvertTo-Csv -NoTypeInformation))
        $lines = @('"group","member"')
        foreach ($gr in @(Get-Wmi Win32_Group 'LocalAccount=True')) {
            try {
                $obj = [ADSI]('WinNT://' + $gr.Domain + '/' + $gr.Name + ',group')
                foreach ($m in @($obj.psbase.Invoke('Members'))) {
                    $p = $m.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $m, $null)
                    $lines += ('"{0}","{1}"' -f $gr.Name, (($p -replace '^WinNT://', '') -replace '/', '\'))
                }
            } catch { }
        }
        [IO.File]::WriteAllLines($g, [string[]]$lines)
        $ok = $true
    } catch { $err = $_.Exception.Message }
    if (-not $ok) { Done users failed $d (Short $err); return }
    Done users ok $d ('{0} accounts; group members of every local group (no passwords)' -f $rows.Count) @('# A list for comparison: passwords are not saved.  Recreate a deleted account with:', 'net user NAME * /add', 'net localgroup GROUP NAME /add')
}

function I-services {
    if (-not (Test-Wmi)) { Done services skipped '' 'WMI not available (not Windows)'; return }
    $f = Jp (Sub 'services') 'services.csv'
    try {
        $rows = @(Get-Wmi Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName, StartName)
        [IO.File]::WriteAllLines($f, [string[]]@($rows | ConvertTo-Csv -NoTypeInformation))
    } catch { Done services failed '' (Short $_.Exception.Message); return }
    Done services ok $f ('{0} services' -f $rows.Count) @('# Service settings are in registry\services.reg.  To set one start mode back:', 'sc.exe config NAME start= auto      # or demand / disabled')
}

# IIS: settings folder, and the physical folders of every site.
$script:WebRoots = @()
function I-iis {
    $src = Jp $S32 'inetsrv\config'
    if (-not (Test-Path -LiteralPath $src)) { Done iis skipped '' 'IIS not installed'; return }
    $d = Jp $B 'iis\config'
    $r = Copy-Tree $src $d
    if ($r -ne 'ok') { Done iis failed $d (Short $r); return }
    # Site folders, for the web item.
    $ah = Jp $src 'applicationHost.config'
    if (Test-Path -LiteralPath $ah) {
        foreach ($m in [regex]::Matches([IO.File]::ReadAllText($ah), 'physicalPath="([^"]+)"')) {
            $p = $m.Groups[1].Value -replace '%SystemDrive%', $env:SystemDrive
            if (-not (Test-CcWindows)) { $p = $p -replace '\\', '/' }   # only when the tests run on Linux
            if ($p -and -not ($script:WebRoots -contains $p)) { $script:WebRoots += $p }
        }
    }
    Done iis ok $d ('applicationHost.config and friends; {0} site folders found' -f $script:WebRoots.Count) @(
        '# Stop IIS, copy the settings back, start it:',
        'iisreset /stop',
        ('Copy-Item ' + (Q (Jp $d '*')) + ' ' + (Q $src) + ' -Recurse -Force'),
        'iisreset /start')
}

function I-web {
    if ($NoWebRoots) { Done web skipped '' '-NoWebRoots'; return }
    $roots = @($script:WebRoots)
    $def = Jp $env:SystemDrive 'inetpub\wwwroot'
    if ($env:SystemDrive -and (Test-Path -LiteralPath $def) -and -not ($roots -contains $def)) { $roots += $def }
    if ($roots.Count -eq 0) { Done web skipped '' 'no website folders'; return }
    $d = Sub 'web'; $done = @(); $bad = @(); $restore = @('# Put a site folder back (overwrites changed files; files added since stay - compare first):')
    foreach ($r0 in $roots) {
        if (-not (Test-Path -LiteralPath $r0)) { continue }
        $name = ($r0 -replace '[:\\/ ]+', '_').Trim('_')
        $r = Copy-Tree $r0 (Jp $d $name)
        if ($r -eq 'ok') { $done += $r0; $restore += ('Copy-Item ' + (Q (Jp (Jp $d $name) '*')) + ' ' + (Q $r0) + ' -Recurse -Force') }
        elseif ($r -like 'big:*') { $bad += ('{0} ({1} MB, over -MaxMB)' -f $r0, $r.Substring(4)) }
        else { $bad += ('{0} ({1})' -f $r0, (Short $r)) }
    }
    if ($done.Count -eq 0) { Done web failed $d ('not saved: ' + ($bad -join '; ')); return }
    $det = ('{0} folders' -f $done.Count); if ($bad.Count -gt 0) { $det += '; NOT saved: ' + ($bad -join '; ') }
    Done web ok $d $det $restore
}

function I-dns {
    $dnsDir = Jp $S32 'dns'
    if (-not (Test-CcCommand 'dnscmd.exe') -and -not (Test-Path -LiteralPath $dnsDir)) { Done dns skipped '' 'DNS server not installed'; return }
    $d = Sub 'dns'
    $zones = @()
    if (Test-CcCommand 'dnscmd.exe') {
        foreach ($l in @(Invoke-CcProgram -FilePath 'dnscmd.exe' -Arguments @('/enumzones'))) {
            if ($l -match '^\s+(\S+)\s+(Primary|Secondary|Stub|Forwarder|Cache)') { if ($matches[1] -ne '.' -and $matches[1] -notmatch '^(TrustAnchors|RootDNSServers)$') { $zones += $matches[1] } }
        }
    }
    $saved = @(); $bad = @(); $restore = @('# Put back one zone: copy its file into the DNS folder, then load it.', '# (An AD-integrated zone: delete the broken one first, then add it back as primary from the file and convert it with dnscmd /zoneresettype ZONE /dsprimary.)')
    foreach ($z in $zones) {
        # dnscmd writes the export into %windir%\System32\dns; it is moved out at once.
        $fn = 'bt-backup-' + $z + '.dns'
        if (Run 'dnscmd.exe' @('/zoneexport', $z, $fn)) {
            $made = Jp $dnsDir $fn
            if (Test-Path -LiteralPath $made) {
                Move-Item -LiteralPath $made -Destination (Jp $d ($z + '.dns')) -Force
                $saved += $z
                $restore += ('Copy-Item ' + (Q (Jp $d ($z + '.dns'))) + ' ' + (Q (Jp $dnsDir ($z + '.dns'))) + '; dnscmd /zoneadd ' + $z + ' /primary /file ' + $z + '.dns /load')
            } else { $bad += $z }
        } else { $bad += $z }
    }
    # Server settings (forwarders and the like) live in the registry.
    if (Test-CcCommand 'reg.exe') { [void](Run 'reg.exe' @('export', 'HKLM\SYSTEM\CurrentControlSet\Services\DNS', (Jp $d 'dns-server-settings.reg'), '/y')) }
    if (Test-Path -LiteralPath $dnsDir) { [void](Copy-Tree $dnsDir (Jp $d 'dns-folder')) }
    if ($saved.Count -eq 0 -and $zones.Count -gt 0) { Done dns failed $d ('no zone exported: ' + ($bad -join ', ')); return }
    $det = ('{0} zones: {1}' -f $saved.Count, ($saved -join ', ')); if ($bad.Count -gt 0) { $det += '; FAILED: ' + ($bad -join ', ') }
    Done dns ok $d $det $restore
}

function I-dhcp {
    $dhcpDir = Jp $S32 'dhcp'
    if (-not (Test-Path -LiteralPath $dhcpDir)) { Done dhcp skipped '' 'DHCP server not installed'; return }
    $d = Sub 'dhcp'
    # Export-DhcpServer (Server 2012 and later) reads the settings while the
    # service keeps answering clients; netsh is the fallback for older servers.
    if (Test-CcCommand 'Export-DhcpServer') {
        $x = Jp $d 'dhcp-export.xml'
        try { Export-DhcpServer -File $x -Leases -Force -ErrorAction Stop }  # ps2-ok (only where the cmdlet exists)
        catch { Done dhcp failed $d (Short $_.Exception.Message); return }
        Done dhcp ok $d 'scopes, options, reservations, leases' @('# Import into the DHCP server (it keeps its own backup of the current settings in the -BackupPath folder):', ('Import-DhcpServer -File ' + (Q $x) + ' -BackupPath ' + (Q (Jp $d 'before-import')) + ' -Leases -Force'))
        return
    }
    $f = Jp $d 'dhcp-export.txt'
    if (-not (Run 'netsh.exe' @('dhcp', 'server', 'export', $f, 'all')) -or -not (Test-Path -LiteralPath $f)) { Done dhcp failed $d (Short $script:LastOut); return }
    Done dhcp ok $d 'scopes, options, reservations, leases' @('# Import into the DHCP server (stop and restart the DHCP service around it if it complains):', ('netsh dhcp server import ' + (Q $f) + ' all'))
}

$IsDC = $os.IsDC -or (Test-Path -LiteralPath (Jp $Win 'SYSVOL'))
function I-gpo {
    if (-not $IsDC) { Done gpo skipped '' 'not a domain controller'; return }
    $d = Sub 'gpo'
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        $all = @(Backup-GPO -All -Path $d -ErrorAction Stop)
        $rep = Jp $d 'gpo-report.html'
        try { Get-GPOReport -All -ReportType Html -Path $rep -ErrorAction Stop } catch { }
    } catch { Done gpo failed $d (Short $_.Exception.Message); return }
    Done gpo ok $d ('{0} Group Policy objects' -f $all.Count) @(
        '# Put back one GPO as it was (by name), or all of them:',
        ('Restore-GPO -Name "GPO NAME" -Path ' + (Q $d)),
        ('Restore-GPO -All -Domain $env:USERDNSDOMAIN -Path ' + (Q $d)))
}

function I-sysvol {
    $src = Jp $Win 'SYSVOL\domain'
    if (-not (Test-Path -LiteralPath $src)) { $src = Jp $Win 'SYSVOL\sysvol' }
    if (-not $IsDC -or -not (Test-Path -LiteralPath $src)) { Done sysvol skipped '' 'not a domain controller'; return }
    $d = Jp $B 'sysvol'
    $r = Copy-Tree $src $d
    if ($r -like 'big:*') { Done sysvol failed $d ('{0} MB, over -MaxMB' -f $r.Substring(4)); return }
    if ($r -ne 'ok') { Done sysvol failed $d (Short $r); return }
    Done sysvol ok $d 'logon scripts and policy files' @('# Prefer Restore-GPO for policies.  For a logon script the red team changed, copy that one file back from:', ('#   ' + $d + '\scripts'))
}

function I-ad {
    if (-not $IsDC) { Done ad skipped '' 'not a domain controller'; return }
    $d = Sub 'ad'
    $n = 0
    try {
        $root = [ADSI]'LDAP://RootDSE'
        $base = [string]$root.defaultNamingContext
        foreach ($kind in @(@('users', '(&(objectCategory=person)(objectClass=user))', @('samaccountname', 'distinguishedname', 'useraccountcontrol', 'memberof', 'admincount', 'description', 'serviceprincipalname')),
                            @('groups', '(objectClass=group)', @('samaccountname', 'distinguishedname', 'member', 'admincount')),
                            @('computers', '(objectClass=computer)', @('samaccountname', 'distinguishedname', 'operatingsystem', 'useraccountcontrol')),
                            @('ous', '(objectClass=organizationalUnit)', @('name', 'distinguishedname', 'gplink')))) {
            $s = New-Object DirectoryServices.DirectorySearcher([ADSI]('LDAP://' + $base), $kind[1])
            $s.PageSize = 1000
            foreach ($p in $kind[2]) { [void]$s.PropertiesToLoad.Add($p) }
            $lines = @((($kind[2] | ForEach-Object { '"' + $_ + '"' }) -join ','))
            foreach ($r in @($s.FindAll())) {
                $vals = @()
                foreach ($p in $kind[2]) { $v = (@($r.Properties[$p]) | ForEach-Object { [string]$_ }) -join '; '; if ($p -eq 'description' -and $v -match '(?i)(pass(word)?|pwd|pw)\s*[:=]') { $v = '(hidden: password-like text)' }; $vals += ('"' + $v.Replace('"', '""') + '"') }
                $lines += ($vals -join ','); $n++
            }
            [IO.File]::WriteAllLines((Jp $d ($kind[0] + '.csv')), [string[]]$lines)
        }
    } catch { Done ad failed $d (Short $_.Exception.Message); return }
    # The Recycle Bin decides whether a deleted user can be brought back.
    $rb = 'unknown'
    try {
        $cfg = [string]$root.configurationNamingContext
        $o = [ADSI]('LDAP://CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,' + $cfg)
        if (@($o.Properties['msDS-EnabledFeatureBL']).Count -gt 0) { $rb = 'on' } else { $rb = 'OFF' }
    } catch { }
    Add-CcFlag -Severity LOW -Section ad -Item 'AD Recycle Bin' -Detail ("AD Recycle Bin is $rb")
    $restore = @('# Lists for comparison.  A deleted user can only come back through the AD Recycle Bin', ("# (now: $rb).  Turning it on CANNOT be undone; do it early if your team agrees:"),
        '#   Enable-ADOptionalFeature "Recycle Bin Feature" -Scope ForestOrConfigurationSet -Target $env:USERDNSDOMAIN',
        '# Then bring a user back:  Get-ADObject -Filter "samaccountname -eq ''NAME''" -IncludeDeletedObjects | Restore-ADObject')
    Done ad ok $d ("$n objects listed; AD Recycle Bin $rb") $restore
}

function I-addb {
    if (-not $AdDatabase) { Done addb skipped '' 'not asked for (-AdDatabase): it would hold every password hash'; return }
    if (-not $IsDC) { Done addb skipped '' 'not a domain controller'; return }
    $d = Jp $B 'ad-database'
    # ntdsutil reads each argument as one command line; a space in the path
    # would split it.
    if ($d.Contains(' ')) { Done addb failed '' "the output path has a space in it ($d); use -Out C:\bt-out"; return }
    if (-not (Run 'ntdsutil.exe' @('activate instance ntds', 'ifm', ('create sysvol full ' + $d), 'quit', 'quit'))) { Done addb failed $d (Short $script:LastOut); return }
    Add-CcFlag -Severity HIGH -Section addb -Item $d -Detail 'this folder holds the AD database with every password hash: copy it off the box with -CopyTo and delete it here'
    Done addb ok $d 'AD database and SYSVOL (install-from-media copy). HOLDS EVERY PASSWORD HASH' @('# Used for an authoritative restore or to build a new DC from media (dcpromo /ReplicaOrNewDomain ...).', '# Do not keep this folder on the DC: delete it after copying it off the box.')
}

function I-paths {
    if ($Path.Count -eq 0) { Done paths skipped '' 'no -Path given'; return }
    $d = Sub 'paths'; $done = @(); $bad = @(); $restore = @()
    foreach ($p in $Path) {
        if (-not (Test-Path -LiteralPath $p)) { $bad += "$p (not found)"; continue }
        $full = Resolve-CcPath $p
        $name = ($full -replace '[:\\/ ]+', '_').Trim('_')
        $r = Copy-Tree $full (Jp $d $name)
        if ($r -eq 'ok') { $done += $full; $restore += ('Copy-Item ' + (Q (Jp $d $name)) + ' ' + (Q $full) + ' -Recurse -Force') }
        elseif ($r -like 'big:*') { $bad += ('{0} ({1} MB, over -MaxMB)' -f $full, $r.Substring(4)) }
        else { $bad += ('{0} ({1})' -f $full, (Short $r)) }
    }
    if ($done.Count -eq 0) { Done paths failed $d ('not saved: ' + ($bad -join '; ')); return }
    $det = ('{0} saved' -f $done.Count); if ($bad.Count -gt 0) { $det += '; NOT saved: ' + ($bad -join '; ') }
    Done paths ok $d $det $restore
}

# ---- Run ----------------------------------------------------------------------
foreach ($i in $AllItems) {
    if (-not (Want $i)) { continue }
    try { & ('I-' + $i) }
    catch { Done $i failed '' ('stopped: ' + (Short $_.Exception.Message)) }
}

# RESTORE.txt, hashes, summary.
$rf = Jp $B 'RESTORE.txt'
$head = @('WN-35 backup of ' + $Cc.Host + ', ' + [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm 'UTC'"),
          'Run these in an elevated PowerShell window, one item at a time, and check the',
          'service still works after each.  Paths are where the backup was made; if you',
          'copied it elsewhere, change the folder at the start of each path.')
[IO.File]::WriteAllLines($rf, [string[]]($head + $script:Restore))

$sums = Jp $B 'SHA256SUMS.txt'
$hl = @()
$bl = $B.Length + 1
foreach ($f in @(Get-ChildItem -LiteralPath $B -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer -and $_.Name -ne 'SHA256SUMS.txt' })) {
    $h = Get-CcSha256 -Path $f.FullName
    if ($h) { $hl += ($h + '  ' + $f.FullName.Substring($bl)) }
}
[IO.File]::WriteAllLines($sums, [string[]]$hl)

$total = [int]((Size $B) / 1MB)
$sum = @()
$sum += ('WN-35 Windows backup  {0}' -f [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm 'UTC'"))
$sum += ('Host: {0}  {1}{2}' -f $Cc.Host, $os.Caption, $(if ($IsDC) { '  (domain controller)' } else { '' }))
$sum += ''
$sum += $script:Lines
$sum += ''
$sum += ('{0} saved, {1} failed, {2} skipped; {3} files, {4} MB' -f $script:Count.ok, $script:Count.failed, $script:Count.skipped, $hl.Count, $total)
$sum += ('Restore commands: ' + $rf)

# Copy off the box.
if ($CopyTo) {
    $dest = Jp $CopyTo (Split-Path -Leaf $B)
    try {
        Copy-Item -LiteralPath $B -Destination $dest -Recurse -Force -ErrorAction Stop
        $n2 = @(Get-ChildItem -LiteralPath $dest -Recurse -Force | Where-Object { -not $_.PSIsContainer }).Count
        if ($n2 -lt $hl.Count + 1) { $sum += ('COPY INCOMPLETE: {0} of {1} files reached {2}' -f $n2, ($hl.Count + 1), $dest); $script:Count.failed++ }
        else { $sum += ('Copied to: ' + $dest) }
    } catch {
        $sum += ('COPY FAILED to {0}: {1}' -f $CopyTo, $_.Exception.Message)
        $script:Count.failed++
    }
} else {
    $sum += 'Not copied off the box: use -CopyTo \\server\share (a red team with admin rights can delete it here).'
    Write-CcLog -Level WARN -Message 'not copied off the box: use -CopyTo \\server\share (a red team with admin rights can delete it here)'
}
if ($AdDatabase -and $script:Count.ok -gt 0 -and (Test-Path -LiteralPath (Jp $B 'ad-database'))) { $sum += 'WARNING: ad-database\ holds every domain password hash. Copy it off the box, then delete it here.' }

[IO.File]::WriteAllLines((Jp $B 'summary.txt'), [string[]]$sum)
if ($CopyTo -and (Test-Path -LiteralPath (Jp $CopyTo (Split-Path -Leaf $B)))) { Copy-Item -LiteralPath (Jp $B 'summary.txt') -Destination (Jp (Jp $CopyTo (Split-Path -Leaf $B)) 'summary.txt') -Force -ErrorAction SilentlyContinue }
if (-not $Quiet) { foreach ($l in $sum) { Write-Host $l } }
Write-Host ('All results: ' + $B)
if ($script:Count.failed -gt 0) { Complete-Cc -ExitCode 5 }
Complete-Cc
