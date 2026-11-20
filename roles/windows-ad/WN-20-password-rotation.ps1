# =============================================================================
# ID:       WN-20
# NAME:     Windows password rotation
# ROLE:     Windows / AD  (wave 2, first 15 minutes)
# KIND:     changes - dry run unless -Apply
# VERSION:  1.1.0
#
# PURPOSE
#   Default and leaked passwords are the red team's first way in.  This gives
#   every enabled account a new password - local accounts on any Windows box,
#   and every domain user when run on a domain controller - and writes the new
#   passwords to ONE file for the captain, never to the screen or the log.
#   Accounts the team must keep as they are can be left out (-Exclude, the
#   protected list), and chosen accounts can get chosen passwords (-Passwords).
#
#   The look and the questions are the same as the Linux scripts (LX-20).
#   QUESTIONS (Enter takes the default in capitals; a parameter answers each):
#     more than 5 accounts: one by one? [R]andom for all / [e]ach one
#     each account: new password?     [r]andom [s]et one (typed twice, hidden)
#                                     [k]eep [a]ll the rest random
#                                     (-Users, -Exclude, -Passwords answer them)
#     apply these changes?            -Apply (Enter = no)
#     no protected list: go on?       -NoProtected (Enter = no)
#
# USAGE
#   powershell -NoProfile -ExecutionPolicy Bypass -File WN-20-password-rotation.ps1 -Out C:\bt-out              dry run
#   powershell ... WN-20-password-rotation.ps1 -Out C:\bt-out -Apply -Exclude mark.jacobs,admin
#   powershell ... WN-20-password-rotation.ps1 -Out C:\bt-out -Apply -Passwords C:\team\sheet.csv
#   Run in an elevated window; on a domain controller as a domain admin.
#
# OPTIONS
#   -Exclude a,b       never touch these accounts
#   -Users a,b         change only these accounts
#                      A name in -Exclude or -Users that is not an account
#                      here STOPS the script before anything changes: a typo
#                      would change the account you meant to keep
#   -IgnoreMissing     only warn about such names (one list for many boxes)
#   -Passwords FILE    chosen passwords: "account password" lines (an older
#                      "account,password" file still works).  Accounts
#                      not in the file get a random one.  Spaces around both
#                      are dropped.  Names not here, and disabled accounts,
#                      are listed and not changed
#   -Length N          random password length (default 16, at least 12)
#   -IncludeMe         also change the account running this script (skipped
#                      by default: you are logged in with it)
#   -IncludeDisabled   also give disabled accounts a new password (they stay
#                      disabled; useful if the red team may turn one back on)
#   -IncludeServices   also change accounts that run services, tasks or IIS
#                      app pools here, or have an SPN (skipped by default:
#                      changing them breaks those services until each one is
#                      given the new password too)
#   -LocalOnly         on a domain controller, the domain accounts are the
#                      only ones; on a member server or workstation this is
#                      the default anyway (domain accounts are changed on a DC)
#   -Print             also show the new passwords on screen at the end
#   -Batch             no questions: the defaults (a dry run unless -Apply)
#   -NoColor           no colours
#   Common options (-Apply, -Out, -Protected, -NoProtected, -ForceScored,
#   -Quiet, -DebugLog) come from the library.
#
# OUTPUTS  (under -Out, one numbered folder per run: passwords-1, -2, ...)
#   output.txt            everything shown on screen (never a password)
#   accounts.txt          account, scope, state, action, note (no passwords)
#   summary.txt           what was changed, skipped and why
#   run.txt               id, host, time
#   passwords.txt         HOST ACCOUNT PASSWORD TIME - only with -Apply,
#                         readable by Administrators and SYSTEM only.  Give it
#                         to the captain, then delete it from this box
#   pending-password.txt  only while ONE account is being changed; left
#                         behind if the script is stopped at that moment:
#                         that account has either its old password or this one
#
# WHAT IT CHANGES  (only with -Apply)
#   Account passwords (ADSI SetPassword: WinNT for local accounts, LDAP for
#   domain accounts).  Nothing else: accounts are not enabled, disabled,
#   unlocked or forced to change their password at next logon (that would
#   break scored logins).  Old passwords cannot be put back - Windows keeps no
#   copy anyone can restore - so passwords.txt is the record.
#
# DEPENDS ON
#   WMI (local accounts, services), ADSI (WinNT and LDAP providers), schtasks.
#   All present on Windows 7 / Server 2008 R2 and later.  No AD module needed.
#   $env:BT_WN20_FAKE names a folder of stand-in accounts for the tests, so
#   they never touch a real account.
#
# TESTED ON
#   PowerShell 7 on Linux against stand-in accounts (tests/wn20.Tests.ps1).
#   NOT yet run on real Windows: run it on a throwaway VM first.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Accounts the scoring engine logs in with MUST be excluded or on the
#     protected list (type account), or scoring breaks.
#   - Service accounts are found only on THIS box (services, tasks, IIS app
#     pools) plus any domain account with an SPN.  A domain account used by a
#     service on ANOTHER box is not seen: exclude it by name.
#   - krbtgt, Guest, DefaultAccount and WDAGUtilityAccount are never changed
#     (krbtgt has its own two-step reset, WN-22).
#   - A password the domain policy rejects (too short, too simple, used
#     before) fails for that account only; the summary says so.
#   - Changing a password does not end sessions already open.
#
# DEBUGGING
#   -DebugLog shows how each account was classified and why.
#   Passwords are never in the log, even with -DebugLog.
# =============================================================================
param(
    [switch]$Apply, [string]$Out, [string]$Protected, [switch]$NoProtected,
    [switch]$ForceScored, [switch]$Quiet, [switch]$DebugLog,
    [string[]]$Exclude = @(),
    [string[]]$Users = @(),
    [switch]$IgnoreMissing,
    [string]$Passwords = '',
    [int]$Length = 16,
    [switch]$IncludeMe,
    [switch]$IncludeDisabled,
    [switch]$IncludeServices,
    [switch]$Print,
    [switch]$Help,
    [switch]$Batch,
    [switch]$NoColor
)

if ($Help) {
    Write-Host 'WN-20 Windows password rotation - new passwords for every enabled account'
    Write-Host '  -Apply               make the changes (default: dry run)'
    Write-Host '  -Exclude a,b         never touch these accounts'
    Write-Host '  -Users a,b           change only these accounts'
    Write-Host '  -IgnoreMissing       warn instead of stopping when a name is not an account here'
    Write-Host '  -Passwords FILE      "account password" lines to use instead of random ones'
    Write-Host '  -Length N            random password length (default 16)'
    Write-Host '  -IncludeMe -IncludeDisabled -IncludeServices -Print'
    Write-Host '  -Batch               no questions: the defaults (a dry run unless -Apply)'
    Write-Host '  -NoColor             no colours'
    Write-Host '  -Out DIR -Protected FILE -NoProtected -ForceScored -Quiet -DebugLog'
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
# Windows PowerShell 5.1 turns an empty list returned from a function into
# $null, and piping $null passes ONE blank item - which the typo check then
# reported as a missing account.  So: no function return, and blanks dropped.
$Exclude = @(@($Exclude) | Where-Object { $_ } | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
$Users = @(@($Users) | Where-Object { $_ } | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
if ($Length -lt 12) { Write-Host '-Length must be 12 or more'; exit 2 }
if ($Passwords -and -not (Test-Path -LiteralPath $Passwords)) { Write-Host "-Passwords: cannot read $Passwords"; exit 2 }

# ---- Start ------------------------------------------------------------------
Initialize-Cc -Id 'WN-20' -Name 'Windows password rotation' -Kind changes -Bound $PSBoundParameters
$Fake = $env:BT_WN20_FAKE
if ($Fake) { Write-CcLog -Level WARN -Message "TEST MODE: stand-in accounts from $Fake; no real account is read or changed" }
elseif ($Cc.Apply) { Assert-CcAdmin }
Use-CcNumberedDir 'passwords'
Write-CcShow -Color Cyan -Text ('WN-20 Windows password rotation | host {0} | results in {1}' -f $Cc.Host, $Cc.RunDir)
Write-CcLegend -Marks @('Yellow=[~] would change', 'Green=[+] changed', 'DarkGray=[-] left alone', 'Red=[x] failed')
$os = Get-CcOsInfo
$IsDC = $os.IsDC
if ($Fake -and (Test-Path -LiteralPath (Join-Path $Fake 'is-dc'))) { $IsDC = $true }
function Lc2($s) { if ($null -eq $s) { return '' }; return ([string]$s).ToLower() }
$me0 = $env:USERNAME; if (-not $me0) { $me0 = $env:USER }
$Me = Lc2 $me0

# ---- Account sources ----------------------------------------------------------
# Every read and write of an account goes through these few functions, so the
# tests can swap in stand-ins ($env:BT_WN20_FAKE) without touching Windows.
#   account object: Name, Scope (local|domain), Sid, Disabled, Spn, Path

function Read-FakeCsv([string]$name) {
    $p = Join-Path $Fake $name
    if (-not (Test-Path -LiteralPath $p)) { return @() }
    return @([IO.File]::ReadAllLines($p) | ConvertFrom-Csv)
}

function Get-Accounts {
    if ($Fake) {
        return @(Read-FakeCsv 'accounts.csv' | ForEach-Object { New-Object PSObject -Property @{ Name = $_.name; Scope = $_.scope; Sid = $_.sid; Disabled = ($_.disabled -eq 'True'); Spn = $_.spn; Path = $_.name } })
    }
    $list = @()
    if ($IsDC) {
        # Domain users through LDAP; no AD module needed.
        $root = [ADSI]'LDAP://RootDSE'
        $s = New-Object DirectoryServices.DirectorySearcher([ADSI]('LDAP://' + [string]$root.defaultNamingContext), '(&(objectCategory=person)(objectClass=user))')
        $s.PageSize = 1000
        foreach ($p in @('samaccountname', 'objectsid', 'useraccountcontrol', 'serviceprincipalname', 'distinguishedname')) { [void]$s.PropertiesToLoad.Add($p) }
        foreach ($r in @($s.FindAll())) {
            $sidBytes = $r.Properties['objectsid'][0]
            $sid = (New-Object Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
            $uac = [int]($r.Properties['useraccountcontrol'][0])
            $list += New-Object PSObject -Property @{ Name = [string]$r.Properties['samaccountname'][0]; Scope = 'domain'; Sid = $sid; Disabled = (($uac -band 2) -ne 0)
                Spn = ((@($r.Properties['serviceprincipalname']) | ForEach-Object { [string]$_ }) -join ' '); Path = ('LDAP://' + [string]$r.Properties['distinguishedname'][0]) }
        }
    } else {
        $q = @()
        if (Test-CcCommand 'Get-WmiObject') { $q = @(Get-WmiObject -Class Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop) }
        else { $q = @(Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop) }  # ps2-ok
        foreach ($u in $q) {
            $list += New-Object PSObject -Property @{ Name = $u.Name; Scope = 'local'; Sid = $u.SID; Disabled = [bool]$u.Disabled; Spn = ''; Path = ('WinNT://' + $env:COMPUTERNAME + '/' + $u.Name + ',user') }
        }
    }
    return $list
}

# Names of accounts that run something on this box: services, scheduled
# tasks and IIS application pools.  Changing their password breaks that
# service until it is given the new one.
function Get-ServiceUsers {
    $set = @{}
    function Add-One([string]$who, [string]$what) {
        $n = (Lc2 $who).Trim()
        if ($n -eq '') { return }
        if ($n.Contains('\')) { $n = $n.Substring($n.LastIndexOf('\') + 1) }
        if ($n.Contains('@')) { $n = $n.Substring(0, $n.IndexOf('@')) }
        if (@('localsystem', 'system', 'localservice', 'networkservice', 'local service', 'network service', 'n/a', 'users', 'interactive', 'everyone') -contains $n) { return }
        if ($n.StartsWith('nt service') -or $n.StartsWith('nt authority')) { return }
        if ($set.ContainsKey($n)) { $set[$n] += ', ' + $what } else { $set[$n] = $what }
    }
    if ($Fake) {
        foreach ($r in @(Read-FakeCsv 'service-users.csv')) { Add-One $r.account $r.what }
        return $set
    }
    try {
        $svc = @()
        if (Test-CcCommand 'Get-WmiObject') { $svc = @(Get-WmiObject -Class Win32_Service -ErrorAction Stop) } else { $svc = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop) }  # ps2-ok
        foreach ($s in $svc) { Add-One $s.StartName ('service ' + $s.Name) }
    } catch { Write-CcLog -Level WARN -Message ('could not list services: ' + $_.Exception.Message) }
    $hdr = @(); for ($i = 0; $i -lt 30; $i++) { $hdr += ('c' + $i) }
    $rows = @(Invoke-CcProgram -FilePath 'schtasks.exe' -Arguments @('/query', '/fo', 'csv', '/v') | Where-Object { $_ -match '^"' } | ConvertFrom-Csv -Header $hdr)
    $first = ''; if ($rows.Count -gt 0) { $first = $rows[0].c14 }
    foreach ($t in $rows) { if ($t.c14 -ne $first) { Add-One $t.c14 ('task ' + $t.c1) } }
    $ah = Join-Path $env:SystemRoot 'System32\inetsrv\config\applicationHost.config'
    if (Test-Path -LiteralPath $ah) {
        foreach ($m in [regex]::Matches([IO.File]::ReadAllText($ah), '<add name="([^"]+)"[^>]*>\s*<processModel[^>]*userName="([^"]+)"')) { Add-One $m.Groups[2].Value ('IIS app pool ' + $m.Groups[1].Value) }
    }
    return $set
}

# Set-Pw account password -> nothing, or throws with Windows' reason.
function Set-Pw($a, [string]$pw) {
    if ($Fake) {
        foreach ($r in @(Read-FakeCsv 'fail.csv')) { if ($r.name -eq $a.Name) { throw $r.reason } }
        if ($env:BT_WN20_SLOW -eq $a.Name) { Start-Sleep -Seconds 60 }
        [IO.File]::AppendAllText((Join-Path $Fake 'set.log'), ($a.Name + "`t" + $pw + "`n"))
        return
    }
    $o = [ADSI]$a.Path
    if ($a.Scope -eq 'domain') { [void]$o.psbase.Invoke('SetPassword', $pw); [void]$o.psbase.CommitChanges() }
    else { [void]$o.SetPassword($pw) }
}

# Test-Pw account password -> 'yes', 'no' or 'unknown' (cannot check here).
function Test-Pw($a, [string]$pw) {
    if ($Fake) {
        $last = ''
        foreach ($l in @([IO.File]::ReadAllLines((Join-Path $Fake 'set.log')))) { $f = $l -split "`t", 2; if ($f[0] -eq $a.Name) { $last = $f[1] } }
        if ($last -eq $pw) { return 'yes' }; return 'no'
    }
    try {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
        $ct = [DirectoryServices.AccountManagement.ContextType]::Machine
        if ($a.Scope -eq 'domain') { $ct = [DirectoryServices.AccountManagement.ContextType]::Domain }
        $pc = New-Object DirectoryServices.AccountManagement.PrincipalContext($ct)
        if ($pc.ValidateCredentials($a.Name, $pw)) { return 'yes' }
        return 'no'
    } catch { return 'unknown' }
}

# ---- Read accounts and decide ---------------------------------------------------
try { $accounts = @(Get-Accounts) } catch { Stop-Cc -Code 3 -Message ('cannot list the accounts: ' + $_.Exception.Message) }
if ($accounts.Count -eq 0) { Stop-Cc -Code 3 -Message 'no accounts found' }
$names = @{}; foreach ($a in $accounts) { $names[(Lc2 $a.Name)] = $a }

# Names typed by hand must exist: a typo in -Exclude would change the account
# the operator meant to keep.
$missing = @(@($Exclude) + @($Users) | Where-Object { $_ -and -not $names.ContainsKey((Lc2 $_)) })
if ($missing.Count -gt 0) {
    if ($IgnoreMissing) { Write-CcLog -Level WARN -Message ('not accounts here (ignored because of -IgnoreMissing): ' + ($missing -join ', ')) }
    else { Stop-Cc -Code 2 -Message ('no such account here: ' + ($missing -join ', ') + ' (named in -Exclude or -Users). Nothing was changed. Fix the spelling, or add -IgnoreMissing') }
}
$exL = @(@($Exclude) | Where-Object { $_ } | ForEach-Object { Lc2 $_ }); $usL = @(@($Users) | Where-Object { $_ } | ForEach-Object { Lc2 $_ })

# Chosen passwords.
$given = @{}; $notes = @()
if ($Passwords) {
    foreach ($l in @([IO.File]::ReadAllLines((Resolve-CcPath $Passwords)))) {
        $t = $l.Trim()
        if ($t -eq '' -or $t.StartsWith('#')) { continue }
        # "account password", or the older "account,password" (a name, then a comma).
        if ($t -match '^[^\s,]+\s*,') { $i = $t.IndexOf(',') } else { $i = $t.IndexOfAny([char[]]@(' ', "`t")) }
        if ($i -lt 1) { continue }
        $n = $t.Substring(0, $i).Trim(); $p = $t.Substring($i + 1).Trim()
        if ($n -match '^(account|user|name)$') { continue }
        if ($p.Length -lt 8) { Stop-Cc -Code 2 -Message "-Passwords: the password for $n is shorter than 8 characters. Nothing was changed" }
        $given[(Lc2 $n)] = $p
        if (-not $names.ContainsKey((Lc2 $n))) { $notes += "$n is in -Passwords but is not an account here" }
    }
}

$svcUsers = Get-ServiceUsers
$never = @{ '500' = ''; '501' = 'Guest'; '502' = 'krbtgt: reset it with its own two-step process (WN-22)'; '503' = 'DefaultAccount (built in, unused)'; '504' = 'WDAGUtilityAccount (built in, unused)' }

$plan = @()
foreach ($a in ($accounts | Sort-Object Name)) {
    $ln = Lc2 $a.Name
    $rid = (([string]$a.Sid) -split '-')[-1]
    $act = 'change'; $why = ''
    if ($rid -ne '500' -and $never.ContainsKey($rid)) { $act = 'skip'; $why = 'never changed: ' + $never[$rid] }
    elseif ($ln -eq 'krbtgt' -or $ln -like 'krbtgt_*') { $act = 'skip'; $why = 'never changed: krbtgt (WN-22)' }
    elseif ($exL -contains $ln) { $act = 'skip'; $why = 'excluded (-Exclude)' }
    elseif ($usL.Count -gt 0 -and -not ($usL -contains $ln)) { $act = 'skip'; $why = 'not in -Users' }
    elseif ($ln -eq $Me -and -not $IncludeMe) { $act = 'skip'; $why = 'the account running this script (-IncludeMe to change it)' }
    elseif ($a.Disabled -and -not $IncludeDisabled) {
        $act = 'skip'; $why = 'disabled (-IncludeDisabled to change it anyway)'
    }
    elseif (-not $IncludeServices -and ($svcUsers.ContainsKey($ln) -or $a.Spn)) {
        $act = 'skip'; $what = $svcUsers[$ln]; if (-not $what) { $what = 'has an SPN: ' + $a.Spn }
        $why = "runs $what (changing it breaks that until the service gets the new password; -IncludeServices to change it)"
    }
    elseif (-not (Test-CcAllowed -Type account -Value $a.Name)) { $act = 'skip'; $why = 'on the protected list' }
    # A password asked for in -Passwords but not set must not go unnoticed.
    if ($act -eq 'skip' -and $given.ContainsKey($ln) -and $why -ne 'excluded (-Exclude)') { $notes += "$($a.Name) is in -Passwords but was NOT changed: $why" }
    $src = 'random'; if ($given.ContainsKey($ln)) { $src = 'from -Passwords' }
    $plan += New-Object PSObject -Property @{ A = $a; Act = $act; Why = $why; Src = $src }
    Write-CcLog -Level DEBUG -Message ('{0} ({1}): {2} {3}' -f $a.Name, $a.Scope, $act, $why)
}
foreach ($n in $notes) { Write-CcLog -Level WARN -Message $n }

# ---- 1/4 The accounts ------------------------------------------------------------
Write-CcHeader ('1/4  accounts ({0}: {1})' -f $(if ($IsDC) { 'domain controller' } else { 'local' }), $accounts.Count)
foreach ($x in $plan) {
    if ($x.Act -eq 'change') { Write-CcShow -Color Yellow -Text ('  [~] {0,-24} {1,-7} new password ({2})' -f $x.A.Name, $x.A.Scope, $x.Src) }
    elseif ($x.Why -notlike 'never changed*') { Write-CcShow -Color DarkGray -Text ('  [-] {0,-24} {1,-7} {2}' -f $x.A.Name, $x.A.Scope, $x.Why) }
}

# ---- 2/4 Questions: each account, then apply ----------------------------------------
Write-CcHeader '2/4  questions (Enter = the default in capitals)'
$todo = @($plan | Where-Object { $_.Act -eq 'change' })
# Many accounts (a domain controller): one question first, so nobody has to
# answer a hundred.
$each = $true
if ($todo.Count -gt 5 -and (Test-CcCanAsk)) {
    $each = ((Read-CcChoice -Question ('{0} accounts get a new password. Go through them one by one?' -f $todo.Count) -Default r -Options @('r=no: a random password for every one of them (the -Passwords ones get theirs)', 'e=yes: ask about each account (random, set one, keep)')) -eq 'e')
}
if ($todo.Count -gt 0 -and $each -and (Test-CcCanAsk)) {
    $rest = $false
    foreach ($x in $todo) {
        if ($rest) { break }
        $ln = Lc2 $x.A.Name
        $dflt = 'r'; if ($given.ContainsKey($ln)) { $dflt = 's' }
        $q = Read-CcChoice -Question ('{0} ({1}): new password?' -f $x.A.Name, $x.A.Scope) -Default $dflt -Options @(
            ('r=random (' + $Length + ' characters, only in passwords.txt)'), $(if ($given.ContainsKey($ln)) { 's=the one from -Passwords' } else { 's=set one: typed twice, not shown' }),
            'k=keep the old password', 'a=all the rest: their default')
        switch ($q) {
            'k' { $x.Act = 'skip'; $x.Why = 'kept (answered k)' }
            'a' { $rest = $true }
            's' {
                if ($given.ContainsKey($ln)) { break }
                while ($true) {
                    $p1 = Read-CcSecret ('      New password for ' + $x.A.Name)
                    $p2 = Read-CcSecret '      Again'
                    if ($p1 -ne $p2) { Write-CcShow -Color Yellow -Text '      [*] The two did not match: type it again'; continue }
                    if ($p1.Length -lt 8) { Write-CcShow -Color Yellow -Text '      [*] At least 8 characters: type it again'; continue }
                    break
                }
                $given[$ln] = $p1; $x.Src = 'typed'; $p1 = ''; $p2 = ''
            }
        }
    }
}
$todo = @($plan | Where-Object { $_.Act -eq 'change' })
if ($todo.Count -gt 0 -and -not $Cc.Apply -and (Test-CcCanAsk)) {
    if (Read-CcAsk -Question ('Apply these {0} change(s)?' -f $todo.Count) -Default N -Yes 'yes, change the passwords now' -No 'no, change nothing (dry run)') {
        if (-not $Cc.Protected -and -not $Cc.NoProtected) {
            Write-CcShow -Color Yellow -Text '[*] No protected list (the accounts the scoring engine logs in with).'
            if (Read-CcAsk -Question 'Change passwords without one?' -Default N -Yes 'yes, go on without a protected list' -No 'no, stop') { $Cc.NoProtected = $true; $Cc.Apply = $true }
        } else { $Cc.Apply = $true }
        if ($Cc.Apply -and -not $Fake) { Assert-CcAdmin }
    }
}

# ---- 3/4 Change -------------------------------------------------------------------
Write-CcHeader $(if ($Cc.Apply) { '3/4  changing' } else { '3/4  dry run: nothing is changed' })
$tab = New-CcTable -Name accounts -Columns @('account', 'scope', 'state', 'action', 'note')
$rowsOut = @()
function Row4($v) { Add-CcTableRow -File $tab -Values $v; $script:rowsOut += ,$v }
$pwFile = Join-Path $Cc.RunDir 'passwords.txt'
$pend = Join-Path $Cc.RunDir 'pending-password.txt'
$shown = @()
$changed = 0; $failed = 0; $would = 0; $skipped = 0

# Make a file readable by Administrators and SYSTEM only, with this header.
function New-Private([string]$p) {
    [IO.File]::WriteAllText($p, ('{0,-16} {1,-24} {2,-24} {3}' -f 'HOST', 'ACCOUNT', 'PASSWORD', 'TIME') + "`r`n")
    if ((Test-CcWindows) -and (Test-CcCommand 'icacls.exe')) {
        [void](Invoke-CcProgram -FilePath 'icacls.exe' -Arguments @($p, '/inheritance:r', '/grant:r', '*S-1-5-32-544:F', '*S-1-5-18:F'))
    }
}

foreach ($x in $plan) {
    $a = $x.A
    $state = 'enabled'; if ($a.Disabled) { $state = 'disabled' }
    if ($x.Act -eq 'skip') { Row4 @($a.Name, $a.Scope, $state, 'skipped', $x.Why); $skipped++; continue }
    if (-not $Cc.Apply) {
        Write-CcLog -Level WOULD -Message ('set a new password ({0}) for {1} account {2}' -f $x.Src, $a.Scope, $a.Name)
        $Cc.Would++; $would++
        Row4 @($a.Name, $a.Scope, $state, 'would change', $x.Src)
        continue
    }
    $pw = $given[(Lc2 $a.Name)]
    if (-not $pw) { $pw = New-CcPassword -Length $Length }
    if (-not (Test-Path -LiteralPath $pwFile)) { New-Private $pwFile }
    # Written BEFORE the change and removed after it: if the script is
    # stopped in between, the password is not lost.
    New-Private $pend
    $line = ('{0,-16} {1,-24} {2,-24} {3}' -f $Cc.Host, $a.Name, $pw, [DateTime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"))
    [IO.File]::AppendAllText($pend, $line + "`r`n")
    $script:Why = ''
    $ok = Invoke-CcChange -Description ('set a new password ({0}) for {1} account {2}' -f $x.Src, $a.Scope, $a.Name) -Secret -Action {
        try { Set-Pw $a $pw } catch { $script:Why = $_.Exception.Message; if ($_.Exception.InnerException) { $script:Why = $_.Exception.InnerException.Message }; throw }
    }
    if ($ok) {
        [IO.File]::AppendAllText($pwFile, $line + "`r`n")
        Remove-Item -LiteralPath $pend -Force
        $chk = Test-Pw $a $pw
        $note = $x.Src; if ($chk -eq 'yes') { $note += '; new password tested' } elseif ($chk -eq 'no') { $note += '; WARNING: the new password did not work in a test logon - check this account' }
        Row4 @($a.Name, $a.Scope, $state, 'changed', $note)
        Write-CcShow -Color Green -Text ('  [+] new password for {0} ({1})' -f $a.Name, $note)
        $changed++
        if ($Print) { $shown += ('  {0,-24} {1}' -f $a.Name, $pw) }
    } else {
        Remove-Item -LiteralPath $pend -Force
        $why = ($script:Why -replace '[\r\n]+', ' ').Trim()
        Write-CcLog -Level ERROR -Message ('{0}: not changed - {1}' -f $a.Name, $why)
        Row4 @($a.Name, $a.Scope, $state, 'FAILED', ('old password still in use: ' + $why))
        Write-CcShow -Color Red -Text ('  [x] {0}: NOT changed - {1}' -f $a.Name, $why)
        $failed++
    }
}

# ---- Summary ---------------------------------------------------------------------
$sum = @()
$sum += ('WN-20 Windows password rotation  {0}  {1}' -f [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm 'UTC'"), $(if ($Cc.Apply) { 'APPLIED' } else { 'DRY RUN' }))
$scope = 'local accounts'; if ($IsDC) { $scope = 'domain accounts (this is a domain controller)' }
$sum += ('Host: {0}   {1}' -f $Cc.Host, $scope)
$sum += ''
$sum += ('{0} changed, {1} would change, {2} failed, {3} skipped' -f $changed, $would, $failed, $skipped)
Format-CcTable -File $tab
foreach ($r in $rowsOut) {
    if ($r[3] -eq 'skipped' -and $r[4] -like 'never changed*') { continue }
    $sum += ('  {0,-12} {1,-24} {2}' -f $r[3], $r[0], $r[4])
}
if ($notes.Count -gt 0) { $sum += ''; $sum += 'Check:'; foreach ($n in $notes) { $sum += ('  ' + $n) } }
$sum += ''
if ($Cc.Apply -and (Test-Path -LiteralPath $pwFile)) {
    $sum += ('New passwords: ' + $pwFile)
    $sum += '  Give this file to the captain, then delete it from this box.'
    $sum += '[!] SCORED ACCOUNTS: submit each new password in the scoring engine (Quotient: password change request) NOW - until then its checks use the old one and fail.'
    $sum += '  Services and scheduled tasks that log in as a changed account need the new password too.'
} elseif (-not $Cc.Apply) {
    $sum += 'Dry run: nothing was changed.  Check the list, then add -Apply.'
}
[IO.File]::WriteAllLines((Join-Path $Cc.RunDir 'summary.txt'), [string[]]$sum)
Write-CcHeader '4/4  summary'
foreach ($l in $sum) {
    $col = ''
    if ($l -like 'WN-20 *') { $col = 'Cyan' } elseif ($l -like '  FAILED*' -or $l -like '[!]*' -or $l -like '*WARNING*') { $col = 'Red' } elseif ($l -like '  changed*') { $col = 'Green' } elseif ($l -like '  would*' -or $l -like 'New passwords*' -or $l -like 'Dry run*') { $col = 'Yellow' } elseif ($l -like '  skipped*') { $col = 'DarkGray' }
    Write-CcShow -Color $col -Text $l
}
# On screen only, never in output.txt or the log.
if ($shown.Count -gt 0) { Write-Host ''; Write-Host 'New passwords (-Print):'; foreach ($l in $shown) { Write-Host $l } }
Write-Host ('All results: ' + $Cc.RunDir)   # always shown, even with -Quiet
Complete-Cc
