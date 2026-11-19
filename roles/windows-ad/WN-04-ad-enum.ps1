# =============================================================================
# ID:       WN-04
# NAME:     Active Directory enum
# ROLE:     Windows / AD
# KIND:     readonly
#
# PURPOSE
#   Takes a fast, read-only picture of Active Directory before the team changes
#   accounts, DNS or Group Policy. Flags privileged membership, risky account
#   settings, service accounts, delegation, logon scripts and replication/DNS
#   failures without recording passwords or password hashes.
#
# USAGE
#   powershell -NoProfile -ExecutionPolicy Bypass -File WN-04-ad-enum.ps1 -Out C:\ccdc-out
#   powershell ... WN-04-ad-enum.ps1 -Out C:\ccdc-out -EventHours 12
#
# OUTPUTS
#   One numbered ad-enum folder containing summary.txt, readable CSV files and
#   raw command output. Nothing is written to Active Directory.
#
# DEPENDS ON
#   Windows PowerShell, ADSI, WMI, repadmin/dcdiag when installed. The Active
#   Directory module is used when present but is not required.
#
# TESTED ON
#   Syntax and no-domain behavior under PowerShell 7. Not yet tested on a real
#   Server 2016/2019 domain controller; use a disposable lab first.
#
# KNOWN LIMITS
#   LDAP paging is limited to 1000 rows on very large domains. ACL analysis is
#   deliberately conservative. Read failures are reported instead of stopping.
# =============================================================================
param(
    [switch]$Apply, [string]$Out, [string]$Protected, [switch]$NoProtected,
    [switch]$ForceScored, [switch]$Quiet, [switch]$DebugLog,
    [int]$EventHours = 24,
    [switch]$Help
)

if ($Help) {
    Write-Host 'WN-04 Active Directory enum - read-only domain, account, group, GPO, DNS and replication inventory'
    Write-Host '  -EventHours N  security-event look-back (default 24)'
    Write-Host '  -Out DIR -Quiet -DebugLog'
    exit 0
}
if ($Apply) { Write-Host 'WN-04 is read-only; do not use -Apply'; exit 2 }
if ($EventHours -lt 1 -or $EventHours -gt 720) { Write-Host '-EventHours must be 1..720'; exit 2 }

# >>> CCDC-LIB
$ccDir = Split-Path -Parent $MyInvocation.MyCommand.Path
while ($ccDir -and -not (Test-Path -LiteralPath (Join-Path (Join-Path $ccDir 'lib') 'lib.ps1'))) { $ccDir = Split-Path -Parent $ccDir }
if (-not $ccDir) { Write-Host 'cannot find lib/lib.ps1 above this script'; exit 3 }
. (Join-Path (Join-Path $ccDir 'lib') 'lib.ps1')
# <<< CCDC-LIB

Initialize-Cc -Id 'WN-04' -Name 'Active Directory enum' -Kind readonly -Bound $PSBoundParameters
Use-CcRunDir
$raw = Join-Path $Cc.RunDir 'raw'
New-Item -ItemType Directory -Path $raw -Force | Out-Null
$script:Facts = @()
$script:Warnings = @()

function Nz($v) { if ($null -eq $v) { return '' }; return [string]$v }
function Save-Lines([string]$name, [string[]]$lines) { [IO.File]::WriteAllLines((Join-Path $raw $name), [string[]]@($lines)) }
function New-Table([string]$name, [string[]]$header) { return (New-CcCsv -Name $name -Header $header) }
function Warn([string]$item, [string]$detail) { $script:Warnings += "$item - $detail"; Add-CcFlag -Severity HIGH -Section 'ad' -Item $item -Detail $detail }
function Look([string]$item, [string]$detail) { Add-CcFlag -Severity MED -Section 'ad' -Item $item -Detail $detail }

# RootDSE is the safest domain test and works without the AD module.
$root = $null
try { $root = [ADSI]'LDAP://RootDSE' } catch { Write-CcLog -Level WARN -Message ('RootDSE unavailable: ' + $_.Exception.Message) }
if ($null -eq $root -or -not $root.defaultNamingContext) {
    $summary = @('WN-04 Active Directory enum', '', 'This computer could not reach an Active Directory domain.', 'Run on MilkFarm or another domain-joined Windows host with domain connectivity.')
    [IO.File]::WriteAllLines((Join-Path $Cc.RunDir 'summary.txt'), [string[]]$summary)
    foreach ($l in $summary) { Write-Host $l }
    Complete-Cc
}

$base = [string]$root.defaultNamingContext
$config = [string]$root.configurationNamingContext
$schema = [string]$root.schemaNamingContext
$domainName = ($base -replace '^DC=', '') -replace ',DC=', '.'
$script:Facts += "Domain: $domainName"
$script:Facts += "Naming context: $base"

function Search-Ad([string]$filter, [string[]]$props) {
    $out = @()
    try {
        $entry = New-Object DirectoryServices.DirectoryEntry("LDAP://$base")
        $s = New-Object DirectoryServices.DirectorySearcher($entry)
        $s.Filter = $filter; $s.PageSize = 1000; $s.SizeLimit = 0
        foreach ($p in $props) { [void]$s.PropertiesToLoad.Add($p) }
        foreach ($r in @($s.FindAll())) {
            $o = New-Object PSObject
            foreach ($p in $props) {
                $v = $r.Properties[$p]
                $text = ''; if ($v -and $v.Count -gt 0) { $text = (@($v) | ForEach-Object { [string]$_ }) -join ' | ' }
                Add-Member -InputObject $o -MemberType NoteProperty -Name $p -Value $text
            }
            $out += $o
        }
    } catch { Write-CcLog -Level WARN -Message ("LDAP search failed ($filter): " + $_.Exception.Message) }
    return $out
}

# Domain/controller facts.
$facts = New-Table 'domain' @('domain','forest','domain_mode','forest_mode','pdc','rid_master','infrastructure_master')
$d = $null
try { $d = [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain() } catch { Write-CcLog -Level WARN -Message ('domain facts: ' + $_.Exception.Message) }
$forestName = ''; $domainMode = ''; $forestMode = ''; $pdc = ''; $rid = ''; $infra = ''
if ($d) {
    $forestName = Nz $d.Forest.Name; $domainMode = Nz $d.DomainMode; $pdc = Nz $d.PdcRoleOwner.Name; $rid = Nz $d.RidRoleOwner.Name; $infra = Nz $d.InfrastructureRoleOwner.Name
    try { $forestMode = Nz $d.Forest.ForestMode } catch { }
}
Add-CcCsvRow -File $facts -Values @($domainName,$forestName,$domainMode,$forestMode,$pdc,$rid,$infra)

$dcCsv = New-Table 'domain_controllers' @('name','site','address','os','global_catalog','roles')
if ($d) {
    foreach ($dc in @($d.DomainControllers)) {
        $roles = ''; try { $roles = (@($dc.Roles) -join ' | ') } catch { }
        Add-CcCsvRow -File $dcCsv -Values @((Nz $dc.Name),(Nz $dc.SiteName),(Nz $dc.IPAddress),(Nz $dc.OSVersion),(Nz $dc.IsGlobalCatalog),$roles)
    }
}

# Users: do not read unicodePwd, supplementalCredentials or hashes.
$userProps = @('samaccountname','distinguishedname','useraccountcontrol','admincount','serviceprincipalname','scriptpath','homedirectory','description','lastlogontimestamp','pwdlastset','whencreated','whenchanged')
$users = @(Search-Ad '(&(objectCategory=person)(objectClass=user))' $userProps)
$userCsv = New-Table 'users' @('name','enabled','admin_count','spn','script','home','created','changed','flags')
foreach ($u in $users) {
    $uac = 0; [void][int]::TryParse((Nz $u.useraccountcontrol), [ref]$uac)
    $flags = @()
    if (($uac -band 2) -ne 0) { $flags += 'disabled' }
    if (($uac -band 32) -ne 0) { $flags += 'password-not-required'; Warn $u.samaccountname 'account does not require a password' }
    if (($uac -band 65536) -ne 0) { $flags += 'password-never-expires'; Look $u.samaccountname 'password never expires' }
    if (($uac -band 128) -ne 0) { $flags += 'reversible-password'; Warn $u.samaccountname 'reversible password encryption is enabled' }
    if (($uac -band 524288) -ne 0) { $flags += 'trusted-for-delegation'; Warn $u.samaccountname 'unconstrained delegation is enabled' }
    if (($uac -band 4194304) -ne 0) { $flags += 'no-preauth'; Warn $u.samaccountname 'Kerberos preauthentication is disabled' }
    if ($u.serviceprincipalname) { $flags += 'service-principal'; Look $u.samaccountname 'user has an SPN; verify it is an expected service identity' }
    if ($u.scriptpath) { $flags += 'logon-script' }
    Add-CcCsvRow -File $userCsv -Values @($u.samaccountname,(($uac -band 2) -eq 0),$u.admincount,$u.serviceprincipalname,$u.scriptpath,$u.homedirectory,$u.whencreated,$u.whenchanged,($flags -join ' | '))
}
$script:Facts += ('Users: ' + $users.Count)

# Privileged groups and recursive membership through LDAP_MATCHING_RULE_IN_CHAIN.
$priv = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','Server Operators','Group Policy Creator Owners','DnsAdmins')
$groupCsv = New-Table 'privileged_members' @('group','member','class','enabled','nested_or_direct')
foreach ($gname in $priv) {
    $safe = $gname.Replace('\','\5c').Replace('*','\2a').Replace('(','\28').Replace(')','\29')
    $groups = @(Search-Ad "(&(objectClass=group)(cn=$safe))" @('distinguishedname','cn'))
    if ($groups.Count -eq 0) { continue }
    $gdn = $groups[0].distinguishedname
    $members = @(Search-Ad "(memberOf:1.2.840.113556.1.4.1941:=$gdn)" @('samaccountname','objectclass','useraccountcontrol','distinguishedname'))
    foreach ($m in $members) {
        $uac = 0; [void][int]::TryParse((Nz $m.useraccountcontrol), [ref]$uac)
        $class = 'object'; if ((Nz $m.objectclass) -match 'group') { $class = 'group' } elseif ((Nz $m.objectclass) -match 'user') { $class = 'user' }
        $enabled = ''; if ($class -eq 'user') { $enabled = (($uac -band 2) -eq 0) }
        Add-CcCsvRow -File $groupCsv -Values @($gname,$m.samaccountname,$class,$enabled,'recursive')
        if ($class -eq 'user' -and $enabled) { Look ($gname + ': ' + $m.samaccountname) 'enabled privileged account; confirm the team expects it' }
    }
}

# GPOs and SYSVOL/logon scripts.
$gpoCsv = New-Table 'gpos' @('name','id','status','modified','owner')
if (Get-Command Get-GPO -ErrorAction SilentlyContinue) {
    try { foreach ($g in @(Get-GPO -All)) { Add-CcCsvRow -File $gpoCsv -Values @($g.DisplayName,$g.Id,$g.GpoStatus,$g.ModificationTime,$g.Owner) } } catch { Write-CcLog -Level WARN -Message ('GPO inventory failed: ' + $_.Exception.Message) }
} else {
    foreach ($g in @(Search-Ad '(&(objectClass=groupPolicyContainer)(displayName=*))' @('displayname','name','whenchanged','gpcfilesyspath'))) {
        Add-CcCsvRow -File $gpoCsv -Values @($g.displayname,$g.name,'',$g.whenchanged,'')
    }
}
$scriptCsv = New-Table 'logon_scripts' @('account','script','sysvol_path','exists','last_write')
foreach ($u in @($users | Where-Object { $_.scriptpath })) {
    $path = "\\$domainName\SYSVOL\$domainName\scripts\$($u.scriptpath)"
    $exists = Test-Path -LiteralPath $path; $last = ''
    if ($exists) { try { $last = (Get-Item -LiteralPath $path).LastWriteTimeUtc.ToString('s') } catch { } } else { Look $u.samaccountname "logon script is configured but not reachable: $path" }
    Add-CcCsvRow -File $scriptCsv -Values @($u.samaccountname,$u.scriptpath,$path,$exists,$last)
}

# Replication and DNS diagnostics are raw evidence, not parsers that pretend
# every localized version has identical text.
foreach ($cmd in @('repadmin.exe','dcdiag.exe')) {
    if (Get-Command $cmd -ErrorAction SilentlyContinue) {
        $args = @('/replsummary'); if ($cmd -like 'dcdiag*') { $args = @('/test:DNS','/e','/v') }
        $text = @(& $cmd @args 2>&1 | ForEach-Object { [string]$_ })
        Save-Lines (($cmd -replace '\.exe$','') + '.txt') $text
        if ($LASTEXITCODE -ne 0 -or (($text -join "`n") -match '(?i)fail|error')) { Look $cmd 'diagnostic output contains a failure or error; inspect raw output' }
    }
}

# High-value Security log events. wevtutil exists on Server 2008 R2+ and does
# not require newer Get-WinEvent syntax.
if (Get-Command wevtutil.exe -ErrorAction SilentlyContinue) {
    $ms = $EventHours * 60 * 60 * 1000
    $ids = '4720,4722,4724,4725,4726,4728,4732,4738,4756,4765,4766,5136,1102'
    $q = "*[System[(EventID=$($ids -replace ',', ' or EventID=')) and TimeCreated[timediff(@SystemTime) <= $ms]]]"
    $ev = @(& wevtutil.exe qe Security "/q:$q" /f:text 2>&1 | ForEach-Object { [string]$_ })
    Save-Lines 'security-high-value.txt' $ev
}

$summary = @('WN-04 Active Directory enum', ('UTC: ' + [DateTime]::UtcNow.ToString('s') + 'Z'), '') + $script:Facts + @('', 'Review first:')
if ($script:Warnings.Count -eq 0) { $summary += '  No automatically classified HIGH findings. Review privileged_members.csv manually.' } else { foreach ($w in $script:Warnings) { $summary += ('  HIGH ' + $w) } }
$summary += @('', 'Next: verify privileged members and dependencies with the host owner; use docs/RESPONSE-MATRIX.md before changing AD.', ('All results: ' + $Cc.RunDir))
[IO.File]::WriteAllLines((Join-Path $Cc.RunDir 'summary.txt'), [string[]]$summary)
foreach ($line in $summary) { Write-Host $line }
Show-CcFlagReport -Max 30
Complete-Cc
