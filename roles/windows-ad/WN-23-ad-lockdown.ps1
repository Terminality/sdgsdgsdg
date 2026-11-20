# =============================================================================
# ID:       WN-23
# NAME:     Account lockdown (Windows / AD)
# ROLE:     Windows / AD  (wave 2, first 15 minutes on the domain controller)
# KIND:     changes - dry run unless -Apply; a revert timer undoes it unless kept
# VERSION:  1.0.0
#
# PURPOSE
#   Red team's favourite moves on a domain controller: add themselves to an
#   admin group, make a new account, or switch on a setting that hands out a
#   crackable hash.  This reads Active Directory and, for each thing it finds,
#   asks what to do:
#
#     admin groups     members of Domain Admins, Enterprise Admins, Schema
#                      Admins, Administrators, Account Operators, Backup
#                      Operators, Server Operators, Print Operators, DnsAdmins
#                      -> remove from the group (yours stay: -Admins)
#     account flags    no Kerberos pre-authentication (AS-REP roasting),
#                      password not required, reversible encryption, trusted
#                      for (unconstrained) delegation -> clear the flag
#     new accounts     made in the last -Hours hours -> disable
#     not approved     enabled accounts not in -Approved (only when given)
#                      -> disable
#     Guest            enabled -> disable
#   and only reports: passwords that never expire, user accounts with an SPN
#   (Kerberoastable), computers trusted for delegation, the krbtgt password
#   age (its reset is WN-22).  Group Policy is NOT read or changed.
#
#   It never changes: the account running it, accounts on the protected list,
#   the built-in Administrator (RID 500) and krbtgt.
#
#   The look and the questions are the same as the Linux scripts (LX-21).
#   QUESTIONS (Enter takes the default in capitals; a parameter answers each):
#     your team's admin accounts      -Admins a,b (Enter = none named)
#     each finding: [f]ix [k]eep [a]ll the rest: their default
#       defaults: fix the flags, Guest, members not in -Admins (when given);
#       keep new accounts and admins when -Admins is not given (could be
#       a teammate)                   -Only / -Skip
#     apply these changes?            -Apply (Enter = no: a dry run)
#
# USAGE
#   powershell -NoProfile -ExecutionPolicy Bypass -File WN-23-ad-lockdown.ps1                        look + dry run
#   powershell ... WN-23-ad-lockdown.ps1 -Apply -Admins Administrator,blueadmin
#   powershell ... WN-23-ad-lockdown.ps1 -Apply -Batch -Admins blueadmin -Approved C:\team\users.txt
#   Run on the domain controller, in an elevated window, as a domain admin.
#
# OPTIONS
#   -Admins a,b        your team's admin accounts: they stay in the admin
#                      groups; every other member is offered for removal
#                      (default: remove).  Without it, each member is asked
#                      (default: keep)
#   -Approved FILE     accounts that may stay enabled, one a line: every other
#                      enabled user is offered for disabling (default: yes)
#   -Hours N           "new" means made in the last N hours (default 24)
#   -Only a,b / -Skip a,b   admins flags new approved guest
#   -Timer SECONDS     revert countdown (default 120); -NoTimer
#   -Batch             no questions: the defaults (a dry run unless -Apply)
#   -NoColor           no colours
#   Common options (-Apply, -Out, -Protected, -NoProtected, -ForceScored,
#   -Quiet, -DebugLog) come from the library.
#
# OUTPUTS  (under -Out, one numbered folder per run: ad-lockdown-1, -2, ...)
#   output.txt      everything shown on screen, without colour
#   findings.txt    level, kind, account, what was found, what was done
#   summary.txt     the summary page
#   run.txt         id, host, time
#   undo.txt, revert.ps1   this run's undo (the revert timer runs it)
#
# WHAT IT CHANGES  (only with -Apply)
#   Group membership (removes a member), userAccountControl flags (disable,
#   clear "no pre-authentication", "password not required", "reversible
#   encryption", "trusted for delegation").  Each change has an undo line.
#   No password is changed (WN-20) and nothing is deleted.
#
# DEPENDS ON
#   ADSI (LDAP), present on every domain controller; no AD module needed.
#   $env:BT_WN23_FAKE names a folder of stand-in AD data (users.csv,
#   groups.csv, computers.csv) for the tests: then nothing real is read or
#   changed.
#
# TESTED ON
#   PowerShell 7 on Linux against stand-in AD data (tests/wn23.Tests.ps1).
#   NOT yet run against a real domain: run it on a throwaway VM first.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Members of the admin groups are read directly; a group nested inside an
#     admin group is shown as a member (its own members are not expanded).
#   - Removing an admin or disabling an account the scoring engine uses breaks
#     scoring: put those accounts on the protected list (type account).
#   - Group Policy (logon scripts, restricted groups) can put a member back:
#     not covered here.
#   - A password that never expires is only reported: changing it could break
#     a service account.
#
# DEBUGGING
#   -DebugLog shows how each account was read and why it was flagged.
# =============================================================================
param(
    [switch]$Apply, [string]$Out, [string]$Protected, [switch]$NoProtected,
    [switch]$ForceScored, [switch]$Quiet, [switch]$DebugLog,
    [string[]]$Admins = @(),
    [string]$Approved = '',
    [int]$Hours = 24,
    [string]$Only = '',
    [string]$Skip = '',
    [int]$Timer = 120,
    [switch]$NoTimer,
    [switch]$Help,
    [switch]$Batch,
    [switch]$NoColor
)

if ($Help) {
    Write-Host 'WN-23 Account lockdown (AD) - admin groups, risky account flags, new and unapproved accounts, Guest'
    Write-Host '  -Admins a,b        your team''s admins: they stay; other members are offered for removal'
    Write-Host '  -Approved FILE     accounts that may stay enabled (one a line); others offered for disabling'
    Write-Host '  -Hours N           "new" = made in the last N hours (default 24)'
    Write-Host '  -Only a,b -Skip a,b  admins flags new approved guest'
    Write-Host '  -Timer SECONDS -NoTimer -Batch -NoColor'
    Write-Host '  -Apply -Out DIR -Protected FILE -NoProtected -ForceScored -Quiet -DebugLog'
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
$AllParts = @('admins', 'flags', 'new', 'approved', 'guest')
$Admins = @(@($Admins) | Where-Object { $_ } | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
$onlyL = @($Only -split '[,\s]+' | Where-Object { $_ } | ForEach-Object { $_.ToLower() })
$skipL = @($Skip -split '[,\s]+' | Where-Object { $_ } | ForEach-Object { $_.ToLower() })
foreach ($n in @($onlyL + $skipL)) { if (-not ($AllParts -contains $n)) { Write-Host ("unknown part '{0}' ({1})" -f $n, ($AllParts -join ' ')); exit 2 } }
if ($Hours -lt 1) { Write-Host '-Hours must be 1 or more'; exit 2 }
if ($Timer -lt 30) { Write-Host '-Timer must be 30 seconds or more'; exit 2 }
if ($Approved -and -not (Test-Path -LiteralPath $Approved)) { Write-Host "-Approved: cannot read $Approved"; exit 2 }
function Want([string]$part) { return (-not ($skipL -contains $part) -and ($onlyL.Count -eq 0 -or $onlyL -contains $part)) }
function Lc($s) { if ($null -eq $s) { return '' }; return ([string]$s).ToLower() }

# ---- Start ------------------------------------------------------------------
Initialize-Cc -Id 'WN-23' -Name 'Account lockdown (AD)' -Kind changes -Bound $PSBoundParameters
$Fake = $env:BT_WN23_FAKE
if ($Fake) { Write-CcLog -Level WARN -Message "TEST MODE: stand-in AD data from $Fake; nothing real is read or changed" }
Use-CcNumberedDir 'ad-lockdown'
Write-CcShow -Color Cyan -Text ('WN-23 Account lockdown (AD) | host {0} | results in {1}' -f $Cc.Host, $Cc.RunDir)
Write-CcLegend
if (-not $Fake) {
    $os = Get-CcOsInfo
    if (-not $os.IsDC) {
        Write-CcShow -Color Yellow -Text '[*] This is not a domain controller: WN-23 only works on one (Vattar). Local accounts: WN-20 and SH-06.'
        Complete-Cc
    }
    if ($Cc.Apply) { Assert-CcAdmin }
}
$me0 = [Environment]::UserName; if (-not $me0) { $me0 = $env:USERNAME }; if (-not $me0) { $me0 = $env:USER }
$Me = Lc $me0

# ---- Reading AD (or the stand-in) -----------------------------------------------
# user: Name, Sid, Uac, Created (DateTime or $null), PwdSet (DateTime or $null), Spn, Dn
# UAC bits: 2 disabled, 32 password not required, 128 reversible encryption,
# 512 normal account, 8192 domain controller, 65536 password never expires,
# 524288 trusted for delegation, 4194304 no Kerberos pre-authentication.
$PrivGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators', 'Backup Operators', 'Server Operators', 'Print Operators', 'DnsAdmins')

function F-Read([string]$n) { $p = Join-Path $Fake $n; if (-not (Test-Path -LiteralPath $p)) { return @() }; return @([IO.File]::ReadAllLines($p) | ConvertFrom-Csv) }
function To-Date($v) { if (-not $v) { return $null }; try { return [DateTime]::Parse([string]$v, [Globalization.CultureInfo]::InvariantCulture) } catch { return $null } }

function Get-Users {
    if ($Fake) {
        return @(F-Read 'users.csv' | ForEach-Object { New-Object PSObject -Property @{ Name = $_.name; Sid = $_.sid; Uac = [int]$_.uac; Created = (To-Date $_.created); PwdSet = (To-Date $_.pwdlastset); Spn = $_.spn; Dn = $_.dn } })
    }
    $root = [ADSI]'LDAP://RootDSE'
    $s = New-Object DirectoryServices.DirectorySearcher([ADSI]('LDAP://' + [string]$root.defaultNamingContext), '(&(objectCategory=person)(objectClass=user))')
    $s.PageSize = 1000
    foreach ($p in @('samaccountname', 'objectsid', 'useraccountcontrol', 'whencreated', 'pwdlastset', 'serviceprincipalname', 'distinguishedname')) { [void]$s.PropertiesToLoad.Add($p) }
    $list = @()
    foreach ($r in @($s.FindAll())) {
        $sid = (New-Object Security.Principal.SecurityIdentifier($r.Properties['objectsid'][0], 0)).Value
        $pw = $null; try { $raw = [int64]$r.Properties['pwdlastset'][0]; if ($raw -gt 0) { $pw = [DateTime]::FromFileTimeUtc($raw) } } catch { }
        $cr = $null; try { $cr = ([DateTime]$r.Properties['whencreated'][0]).ToUniversalTime() } catch { }
        $list += New-Object PSObject -Property @{ Name = [string]$r.Properties['samaccountname'][0]; Sid = $sid; Uac = [int]$r.Properties['useraccountcontrol'][0]; Created = $cr; PwdSet = $pw
            Spn = ((@($r.Properties['serviceprincipalname']) | ForEach-Object { [string]$_ }) -join ' '); Dn = [string]$r.Properties['distinguishedname'][0] }
    }
    return $list
}
# Get-Members GROUP -> @(@{ Name; Dn }) of its direct members.
function Get-Members([string]$g) {
    if ($Fake) { return @(F-Read 'groups.csv' | Where-Object { $_.group -eq $g } | ForEach-Object { @{ Name = $_.member; Dn = ('CN=' + $_.member) } }) }
    $root = [ADSI]'LDAP://RootDSE'
    $s = New-Object DirectoryServices.DirectorySearcher([ADSI]('LDAP://' + [string]$root.defaultNamingContext), ('(&(objectClass=group)(samaccountname=' + $g + '))'))
    [void]$s.PropertiesToLoad.Add('member'); [void]$s.PropertiesToLoad.Add('distinguishedname')
    $r = $s.FindOne()
    if (-not $r) { return @() }
    $script:GroupDn[$g] = [string]$r.Properties['distinguishedname'][0]
    $out = @()
    foreach ($m in @($r.Properties['member'])) { $o = [ADSI]('LDAP://' + $m); $out += @{ Name = [string]$o.sAMAccountName; Dn = [string]$m } }
    return $out
}
# Computers trusted for unconstrained delegation that are not domain controllers.
function Get-DelegComputers {
    if ($Fake) { return @(F-Read 'computers.csv' | Where-Object { ([int]$_.uac -band 524288) -and -not ([int]$_.uac -band 8192) } | ForEach-Object { $_.name }) }
    $root = [ADSI]'LDAP://RootDSE'
    $s = New-Object DirectoryServices.DirectorySearcher([ADSI]('LDAP://' + [string]$root.defaultNamingContext), '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))')
    [void]$s.PropertiesToLoad.Add('samaccountname')
    return @($s.FindAll() | ForEach-Object { [string]$_.Properties['samaccountname'][0] })
}

# ---- Changing AD (or the stand-in), each with its undo line ------------------------
$script:GroupDn = @{}
function Fake-Uac([string]$name, [int]$uac) {
    $f = Join-Path $Fake 'users.csv'; $rows = @(Import-Csv -LiteralPath $f)
    foreach ($x in $rows) { if ($x.name -eq $name) { $x.uac = [string]$uac } }
    $rows | Export-Csv -LiteralPath $f -NoTypeInformation
}
function Set-Uac($u, [int]$new) {
    if ($Fake) {
        Add-CcUndo -Description ('userAccountControl of {0} back to {1}' -f $u.Name, $u.Uac) -Command ('$f = ' + (ConvertTo-CcQuoted (Join-Path $Fake 'users.csv')) + '; $r = @(Import-Csv -LiteralPath $f); foreach ($x in $r) { if ($x.name -eq ' + (ConvertTo-CcQuoted $u.Name) + ') { $x.uac = ''' + $u.Uac + ''' } }; $r | Export-Csv -LiteralPath $f -NoTypeInformation')
        Fake-Uac $u.Name $new; return
    }
    Add-CcUndo -Description ('userAccountControl of {0} back to {1}' -f $u.Name, $u.Uac) -Command ('$o = [ADSI]' + (ConvertTo-CcQuoted ('LDAP://' + $u.Dn)) + '; $o.Put(''userAccountControl'', ' + $u.Uac + '); $o.SetInfo()')
    $o = [ADSI]('LDAP://' + $u.Dn); $o.Put('userAccountControl', $new); $o.SetInfo()
}
function Remove-Member([string]$g, $m) {
    if ($Fake) {
        $f = Join-Path $Fake 'groups.csv'
        Add-CcUndo -Description ('{0} back in {1}' -f $m.Name, $g) -Command ('Add-Content -LiteralPath ' + (ConvertTo-CcQuoted $f) + ' -Value ''"' + $g + '","' + $m.Name + '"''')
        $rows = @(Import-Csv -LiteralPath $f | Where-Object { -not ($_.group -eq $g -and $_.member -eq $m.Name) })
        if ($rows.Count -gt 0) { $rows | Export-Csv -LiteralPath $f -NoTypeInformation } else { [IO.File]::WriteAllText($f, "group,member`r`n") }
        return
    }
    $gd = $script:GroupDn[$g]
    Add-CcUndo -Description ('{0} back in {1}' -f $m.Name, $g) -Command ('([ADSI]' + (ConvertTo-CcQuoted ('LDAP://' + $gd)) + ').Add(' + (ConvertTo-CcQuoted ('LDAP://' + $m.Dn)) + ')')
    ([ADSI]('LDAP://' + $gd)).Remove('LDAP://' + $m.Dn)
}

# ---- 1/4 Looking --------------------------------------------------------------------
Write-CcHeader '1/4  looking'
try { $users = @(Get-Users) } catch { Stop-Cc -Code 3 -Message ('cannot read the AD users: ' + $_.Exception.Message) }
$byName = @{}; foreach ($u in $users) { $byName[(Lc $u.Name)] = $u }
$adL = @($Admins | ForEach-Object { Lc $_ })
$missing = @($Admins | Where-Object { -not $byName.ContainsKey((Lc $_)) })
if ($missing.Count -gt 0) { Stop-Cc -Code 2 -Message ('-Admins: no such account: ' + ($missing -join ', ') + ' (a typo would remove the admin you meant to keep). Nothing was changed') }
$approvedL = @()
if ($Approved) { $approvedL = @([IO.File]::ReadAllLines((Resolve-CcPath $Approved)) | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') } | ForEach-Object { Lc ($_ -split '[\s,]+')[0] }) }
$now = [DateTime]::UtcNow

# Never touched: the running account, RID 500, krbtgt, protected accounts.
function Untouchable($name, $sid) {
    $ln = Lc $name; $rid = ([string]$sid -split '-')[-1]
    if ($ln -eq $Me) { return 'the account running this script' }
    if ($rid -eq '500') { return 'the built-in Administrator' }
    if ($ln -eq 'krbtgt') { return 'krbtgt (its reset is WN-22)' }
    if ($script:Cc.Protected -and (Test-CcProtected -Type account -Value $name)) { return 'on the protected list' }
    return ''
}
# A finding: Level, Kind, Name, What, Fix ('' = report only), Default (f|k), Act (a scriptblock-free key)
$finds = New-Object System.Collections.ArrayList
function Find([string]$lvl, [string]$kind, [string]$name, [string]$what, [string]$fix, [string]$def, [string]$key, [string]$arg) {
    [void]$finds.Add((New-Object PSObject -Property @{ Level = $lvl; Kind = $kind; Name = $name; What = $what; Fix = $fix; Def = $def; Key = $key; Arg = $arg; Done = '' }))
}

$script:MemberObj = @{}
if (Want 'admins') {
    foreach ($g in $PrivGroups) {
        $mem = @(Get-Members $g)
        if ($mem.Count -eq 0) { continue }
        Write-CcShow -Text ('  {0}: {1}' -f $g, (($mem | ForEach-Object { $_.Name }) -join ', '))
        foreach ($m in $mem) {
            $ln = Lc $m.Name
            $u = $byName[$ln]; $sid = ''; if ($u) { $sid = $u.Sid }
            $why = Untouchable $m.Name $sid
            if ($why) { continue }
            if ($adL -contains $ln) { continue }
            if (@('domain admins', 'enterprise admins') -contains $ln -and $g -eq 'Administrators') { continue }   # the built-in nesting
            $new = ($u -and $u.Created -and ($now - $u.Created).TotalHours -le $Hours)
            $lvl = 'MED'; $d = 'k'; $note = 'not named in -Admins: yours?'
            if ($adL.Count -gt 0) { $lvl = 'HIGH'; $d = 'f'; $note = 'not one of your -Admins' }
            if ($new) { $lvl = 'HIGH'; $note = ('made {0:N0} h ago - ' -f ($now - $u.Created).TotalHours) + $note }
            Find $lvl 'admin group' $m.Name ('{0} is in {1} ({2})' -f $m.Name, $g, $note) ('remove ' + $m.Name + ' from ' + $g) $d 'remove' ($g + '|' + $m.Name)
            $script:MemberObj[$g + '|' + $m.Name] = $m
        }
    }
}
foreach ($u in $users) {
    $why = Untouchable $u.Name $u.Sid
    $en = -not ($u.Uac -band 2)
    if (Want 'flags') {
        foreach ($f in @(@(4194304, 'HIGH', 'no Kerberos pre-authentication: anyone can ask for a hash of its password and crack it (AS-REP roasting)', 'require Kerberos pre-authentication'),
                         @(32, 'HIGH', 'password not required: it may have an empty password', 'require a password'),
                         @(128, 'HIGH', 'password stored with reversible encryption', 'stop reversible encryption (takes effect at the next password change)'),
                         @(524288, 'HIGH', 'trusted for unconstrained delegation: its tickets let it act as any user who logs in to it', 'stop unconstrained delegation'))) {
            if (-not ($u.Uac -band $f[0])) { continue }
            if ($why) { Write-CcShow -Color DarkGray -Text ('  [-] {0}: {1} - left: {2}' -f $u.Name, $f[2], $why); continue }
            Find $f[1] 'account flag' $u.Name ('{0}: {1}' -f $u.Name, $f[2]) ($f[3] + ' for ' + $u.Name) 'f' 'clear' ([string]$f[0])
        }
        if ($en -and ($u.Uac -band 65536) -and $u.Name -ne 'krbtgt') { Find 'LOW' 'account flag' $u.Name ('{0}: password never expires (reported only: a service account may need it)' -f $u.Name) '' 'k' '' '' }
        if ($en -and $u.Spn -and (Lc $u.Name) -ne 'krbtgt') { Find 'MED' 'kerberoast' $u.Name ('{0} has an SPN ({1}): anyone in the domain can get a crackable hash - give it a long password (WN-20)' -f $u.Name, $u.Spn) '' 'k' '' '' }
    }
    if ((Want 'new') -and $en -and $u.Created -and ($now - $u.Created).TotalHours -le $Hours -and -not $why) {
        Find 'HIGH' 'new account' $u.Name ('{0} was made {1:N0} h ago - a teammate, or red team?' -f $u.Name, ($now - $u.Created).TotalHours) ('disable ' + $u.Name) 'k' 'disable' ''
    }
    if ((Want 'approved') -and $approvedL.Count -gt 0 -and $en -and -not $why -and -not ($approvedL -contains (Lc $u.Name)) -and (Lc $u.Name) -ne 'guest') {
        Find 'MED' 'not approved' $u.Name ('{0} is enabled but not in -Approved' -f $u.Name) ('disable ' + $u.Name) 'f' 'disable' ''
    }
    if ((Want 'guest') -and $en -and ((Lc $u.Name) -eq 'guest' -or ([string]$u.Sid) -like '*-501')) {
        Find 'HIGH' 'guest' $u.Name 'the Guest account is enabled' 'disable Guest' 'f' 'disable' ''
    }
}
if (Want 'flags') {
    foreach ($c in @(Get-DelegComputers)) { Find 'MED' 'delegation' $c ('computer {0} is trusted for unconstrained delegation (not a domain controller): change it in its properties (Delegation tab)' -f $c) '' 'k' '' '' }
}
$kt = $byName['krbtgt']
if ($kt -and $kt.PwdSet) { $days = [int]($now - $kt.PwdSet).TotalDays; $lv = 'LOW'; if ($days -gt 180) { $lv = 'MED' }; Find $lv 'krbtgt' 'krbtgt' ('krbtgt password is {0} days old: a stolen copy makes golden tickets until it is reset twice (WN-22)' -f $days) '' 'k' '' '' }

$order = @{ HIGH = 1; MED = 2; LOW = 3 }
$sorted = @($finds | Sort-Object @{ Expression = { $order[$_.Level] } }, Kind, Name)
foreach ($x in $sorted) {
    $c = @{ HIGH = 'Red'; MED = 'Yellow'; LOW = 'DarkGray' }[$x.Level]; $m = @{ HIGH = '[!]'; MED = '[*]'; LOW = '[-]' }[$x.Level]
    Write-CcShow -Color $c -Text ('  {0} {1,-4} {2}' -f $m, $x.Level, $x.What)
}
if ($sorted.Count -eq 0) { Write-CcShow -Color Green -Text '  [ok] nothing found' }

# ---- 2/4 Questions -------------------------------------------------------------------
Write-CcHeader '2/4  questions (Enter = the default in capitals)'
$fixable = @($sorted | Where-Object { $_.Fix })
$rest = $false
foreach ($x in $fixable) {
    $choice = $x.Def
    if (-not $rest -and (Test-CcCanAsk)) {
        $choice = Read-CcChoice -Question ('{0} {1}: {2}?' -f $x.Level, $x.Kind, $x.What) -Default $x.Def -Options @(('f=fix it: ' + $x.Fix), 'k=keep it as it is', 'a=all the rest: their default')
        if ($choice -eq 'a') { $rest = $true; $choice = $x.Def }
    } elseif (-not (Test-CcCanAsk)) {
        Write-CcShow -Color Cyan -Text ('[?] {0}: {1} -> {2} (default)' -f $x.Kind, $x.What, $(if ($x.Def -eq 'f') { 'fix' } else { 'keep' }))
    }
    $x.Done = $(if ($choice -eq 'f') { 'chosen' } else { 'kept' })
}
$todo = @($fixable | Where-Object { $_.Done -eq 'chosen' })
if ($todo.Count -gt 0 -and -not $Cc.Apply -and (Test-CcCanAsk)) {
    if (Read-CcAsk -Question ('Apply these {0} change(s)?' -f $todo.Count) -Default N -Yes 'yes, change AD now (a revert timer runs)' -No 'no, change nothing (dry run)') {
        if (-not $Cc.Protected -and -not $Cc.NoProtected) {
            Write-CcShow -Color Yellow -Text '[*] No protected list (the accounts the scoring engine logs in with).'
            if (Read-CcAsk -Question 'Change AD without one?' -Default N -Yes 'yes, go on without a protected list' -No 'no, stop') { $Cc.NoProtected = $true; $Cc.Apply = $true }
        } else { $Cc.Apply = $true }
        if ($Cc.Apply -and -not $Fake) { Assert-CcAdmin }
    }
}

# ---- 3/4 Changes ---------------------------------------------------------------------
Write-CcHeader $(if ($Cc.Apply) { '3/4  changing' } else { '3/4  dry run: nothing is changed' })
$ok = 0; $bad = 0
if ($todo.Count -eq 0) { Write-CcShow -Color Green -Text '  [ok] nothing to change' }
elseif (-not $Cc.Apply) {
    foreach ($x in $todo) { Write-CcShow -Color Yellow -Text ('  [~] ' + $x.Fix); $Cc.Would++; $x.Done = 'would ' + $x.Fix }
    Write-CcShow -Color DarkGray -Text '  Dry run: nothing was changed. Run again with -Apply.'
} else {
    if (-not $NoTimer) { Start-CcTimer -Seconds $Timer }
    foreach ($x in $todo) {
        $xx = $x
        $r = Invoke-CcChange -Description $x.Fix -Action {
            $u = $byName[(Lc $xx.Name)]
            switch ($xx.Key) {
                'remove'  { $p = $xx.Arg -split '\|', 2; Remove-Member $p[0] $script:MemberObj[$xx.Arg] }
                'clear'   { Set-Uac $u ($u.Uac -band (-bnot [int]$xx.Arg)); $u.Uac = ($u.Uac -band (-bnot [int]$xx.Arg)) }
                'disable' { Set-Uac $u ($u.Uac -bor 2); $u.Uac = ($u.Uac -bor 2) }
            }
        }
        if ($r) { $ok++; $x.Done = 'done: ' + $x.Fix; Write-CcShow -Color Green -Text ('  [+] ' + $x.Fix) }
        else { $bad++; $x.Done = 'FAILED: ' + $x.Fix; Write-CcShow -Color Red -Text ('  [x] FAILED: ' + $x.Fix) }
    }
}

# ---- 4/4 Summary ---------------------------------------------------------------------
$tab = New-CcTable -Name findings -Columns @('level', 'kind', 'account', 'found', 'done')
foreach ($x in $sorted) { Add-CcTableRow -File $tab -Values @($x.Level, $x.Kind, $x.Name, $x.What, $(if ($x.Done) { $x.Done } elseif ($x.Fix) { 'kept' } else { 'reported only' })) }
Format-CcTable -File $tab
$sum = @()
$sum += ('WN-23 Account lockdown (AD)  {0}  {1}' -f [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm 'UTC'"), $(if ($Cc.Apply) { 'APPLIED' } else { 'DRY RUN' }))
$sum += ('Found: {0} HIGH, {1} MED, {2} LOW' -f @($sorted | Where-Object { $_.Level -eq 'HIGH' }).Count, @($sorted | Where-Object { $_.Level -eq 'MED' }).Count, @($sorted | Where-Object { $_.Level -eq 'LOW' }).Count)
foreach ($x in $sorted) { if ($x.Level -ne 'LOW') { $sum += ('  {0,-4} {1}  -> {2}' -f $x.Level, $x.What, $(if ($x.Done) { $x.Done } elseif ($x.Fix) { 'kept' } else { 'reported only' })) } }
if ($Cc.Apply) { $sum += ''; $sum += ('Done: {0}   Failed: {1}' -f $ok, $bad) }
$sum += ''
$sum += 'Next: new passwords for the domain accounts (WN-20); krbtgt reset (WN-22). Group Policy is not checked here.'
[IO.File]::WriteAllLines((Join-Path $Cc.RunDir 'summary.txt'), [string[]]$sum)
Write-CcHeader '4/4  summary'
foreach ($l in $sum) {
    $col = ''
    if ($l -like 'WN-23 *') { $col = 'Cyan' } elseif ($l -like '  HIGH*' -or $l -like '*FAILED*') { $col = 'Red' } elseif ($l -like '  MED*') { $col = 'Yellow' }
    Write-CcShow -Color $col -Text $l
}
if ($Cc.Apply -and $todo.Count -gt 0) { [void](Complete-CcTimer) }
Write-Host ('All results: ' + $Cc.RunDir)   # always shown, even with -Quiet
if ($bad -gt 0) { Complete-Cc -ExitCode 5 }
Complete-Cc
