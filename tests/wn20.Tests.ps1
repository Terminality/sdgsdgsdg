# =============================================================================
# Tests for WN-20 Windows password rotation.
#   pwsh -NoProfile -File tests/wn20.Tests.ps1
#
# Every account read and password change goes through $env:BT_WN20_FAKE:
# a folder with accounts.csv (the accounts), service-users.csv (accounts that
# run services or tasks), fail.csv (accounts whose change fails, with the
# reason) and set.log (every password "set", which the test reads back).  No
# real account is read or changed, on Linux or on Windows.
# =============================================================================
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
$wn20 = Join-Path (Join-Path (Join-Path $root 'roles') 'windows-ad') 'WN-20-password-rotation.ps1'
$psExe = (Get-Process -Id $PID).Path
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('cctest_wn20_' + $PID)
$out = Join-Path $tmp 'out'; $fake = Join-Path $tmp 'fake'
New-Item -ItemType Directory -Path $fake -Force | Out-Null
$env:BT_SKIP_VERIFY = '1'; $env:BT_WN20_FAKE = $fake
$script:pass = 0; $script:fail = 0
function T-Start($t) { Write-Host "  -- $t" }
function T-Eq($got, $want, $label) { if ("$got" -ceq "$want") { $script:pass++ } else { $script:fail++; Write-Host "     FAIL: $label"; Write-Host "           got [$got], wanted [$want]" } }
function T-True($cond, $label) { if ($cond) { $script:pass++ } else { $script:fail++; Write-Host "     FAIL: $label" } }
function T-Has($text, $needle, $label) { T-True ("$text".Contains($needle)) "$label (missing [$needle])" }
function T-HasNot($text, $needle, $label) { T-True (-not "$text".Contains($needle)) "$label (found [$needle])" }
function Run([string[]]$a) {
    $all = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $wn20) + @($a)
    $text = (& $psExe @all 2>&1 | Out-String)
    $dir = ''; if ($text -match 'All results: (\S+)') { $dir = $matches[1].Trim() }
    return @{ Code = $LASTEXITCODE; Text = $text; Dir = $dir }
}
# Rows dir -> the rows of accounts.txt (a " | " table) as hashtables.
function Rows($dir) {
    $lines = @(Get-Content -LiteralPath (Join-Path $dir 'accounts.txt'))
    $h = @($lines[0] -split '\|' | ForEach-Object { $_.Trim() }); $out = @()
    foreach ($l in @($lines | Select-Object -Skip 1)) { $v = @($l -split '\|' | ForEach-Object { $_.Trim() }); $r = @{}; for ($i = 0; $i -lt $h.Count; $i++) { $r[$h[$i]] = $v[$i] }; $out += $r }
    return $out
}
function Row1($dir, $name) { foreach ($r in @(Rows $dir)) { if ($r.account -eq $name) { return $r } }; return @{} }
function Act($dir, $name) { return (Row1 $dir $name).action }
function SetPw($name) { $p = Join-Path $fake 'set.log'; $last = $null; if (Test-Path -LiteralPath $p) { foreach ($l in [IO.File]::ReadAllLines($p)) { $f = $l -split "`t", 2; if ($f[0] -eq $name) { $last = $f[1] } } }; return $last }
function Reset {
    Remove-Item -LiteralPath (Join-Path $fake 'set.log') -Force -ErrorAction SilentlyContinue
    [IO.File]::WriteAllText((Join-Path $fake 'set.log'), '')
}
$me = $env:USERNAME; if (-not $me) { $me = $env:USER }
[IO.File]::WriteAllLines((Join-Path $fake 'accounts.csv'), [string[]]@(
    'name,scope,sid,disabled,spn',
    'Administrator,local,S-1-5-21-1-2-3-500,False,',
    'Guest,local,S-1-5-21-1-2-3-501,False,',
    'DefaultAccount,local,S-1-5-21-1-2-3-503,True,',
    'WDAGUtilityAccount,local,S-1-5-21-1-2-3-504,True,',
    'mark.jacobs,local,S-1-5-21-1-2-3-1001,False,',
    'alice,local,S-1-5-21-1-2-3-1002,False,',
    'bob,local,S-1-5-21-1-2-3-1003,False,',
    'olduser,local,S-1-5-21-1-2-3-1004,True,',
    'svc_sql,local,S-1-5-21-1-2-3-1005,False,',
    'svc_web,local,S-1-5-21-1-2-3-1006,False,HTTP/web01',
    'scoring,local,S-1-5-21-1-2-3-1007,False,',
    'picky,local,S-1-5-21-1-2-3-1008,False,',
    ($me + ',local,S-1-5-21-1-2-3-1009,False,')))
[IO.File]::WriteAllLines((Join-Path $fake 'service-users.csv'), [string[]]@('account,what', 'CORP\svc_sql,service MSSQLSERVER', 'NT AUTHORITY\SYSTEM,service x'))
[IO.File]::WriteAllLines((Join-Path $fake 'fail.csv'), [string[]]@('name,reason', 'picky,The password does not meet the password policy requirements.'))
$prot = Join-Path $tmp 'protected.csv'
[IO.File]::WriteAllLines($prot, [string[]]@('type,value,note', 'account,scoring,the scoring engine logs in as this'))
Reset

T-Start 'options and typo check'
$r = Run @('-Out', $out, '-Length', '8'); T-Eq $r.Code 2 '-Length under 12 exits 2'
$r = Run @('-Out', $out, '-Apply', '-Protected', $prot, '-Exclude', 'mark.jacob'); T-Eq $r.Code 2 'a misspelled -Exclude name exits 2'
T-Has $r.Text 'no such account here: mark.jacob' 'and names it'
T-Eq (SetPw 'mark.jacobs') '' 'nothing was changed'
$r = Run @('-Out', $out, '-Users', 'alice,nobody'); T-Eq $r.Code 2 'a misspelled -Users name exits 2'
$r = Run @('-Out', $out, '-Apply'); T-Eq $r.Code 3 '-Apply without a protected list is refused'

T-Start 'dry run'
$r = Run @('-Out', $out, '-Protected', $prot)
T-Eq $r.Code 0 'exits 0'
T-Has $r.Text 'DRY RUN' 'says it is a dry run'
T-Eq (Act $r.Dir 'alice') 'would change' 'alice would change'
T-Eq ([IO.File]::ReadAllText((Join-Path $fake 'set.log'))) '' 'nothing set'
T-True (-not (Test-Path -LiteralPath (Join-Path $r.Dir 'passwords.txt'))) 'no passwords file in a dry run'

T-Start 'apply with exclusions, a password sheet and the protected list'
$sheet = Join-Path $tmp 'sheet.csv'
[IO.File]::WriteAllLines($sheet, [string[]]@('# account,password', 'account,password', ' alice ,  Team-Alice-Pass-26  ', 'olduser,Should-Not-Be-Set-1', 'ghost,Nobody-Home-12345', 'bob,Has,Comma"Quote-99', 'svc_sql,Sql-Service-Pass-26', 'mark.jacobs,Excluded-Anyway-26'))
$r = Run @('-Out', $out, '-Apply', '-Protected', $prot, '-Exclude', 'mark.jacobs,Administrator', '-Passwords', $sheet)
T-Has $r.Text 'SCORED ACCOUNTS: submit each new password in the scoring engine' 'the summary says to submit scored passwords to the scoring engine'
$d = $r.Dir
T-Eq $r.Code 5 'exits 5 because one change failed'
T-Eq (SetPw 'mark.jacobs') '' 'mark.jacobs (excluded) untouched'
T-Eq (SetPw 'Administrator') '' 'every name in the -Exclude list counts'
T-Eq (SetPw 'alice') 'Team-Alice-Pass-26' 'alice got the sheet password, spaces dropped'
T-Eq (SetPw 'bob') 'Has,Comma"Quote-99' 'a sheet password may hold a comma and a quote'
T-Eq (SetPw 'olduser') '' 'a disabled account is not given the sheet password'
T-Has $r.Text 'olduser is in -Passwords but was NOT changed: disabled' 'and that is reported'
T-Has $r.Text 'svc_sql is in -Passwords but was NOT changed: runs service' 'a sheet password for a skipped service account is reported'
T-HasNot $r.Text 'mark.jacobs is in -Passwords' 'an account you excluded yourself is not nagged about'
T-Has $r.Text 'ghost is in -Passwords but is not an account here' 'a sheet name missing here is reported'
T-Eq (SetPw 'Guest') '' 'Guest never changed'
T-Eq (SetPw 'DefaultAccount') '' 'DefaultAccount never changed'
T-Eq (SetPw 'svc_sql') '' 'an account that runs a service is skipped'
T-Has (Row1 $d 'svc_sql').note 'service MSSQLSERVER' 'and the service is named'
T-Eq (SetPw 'svc_web') '' 'an account with an SPN is skipped'
T-Eq (SetPw 'scoring') '' 'a protected account is skipped'
T-Eq (Act $d 'scoring') 'skipped' 'listed as skipped'
T-Eq (SetPw $me) '' 'the account running the script is skipped'
T-Eq (Act $d 'picky') 'FAILED' 'a rejected password is FAILED'
T-Has $r.Text 'does not meet the password policy' "Windows' reason is shown"
$pf = [IO.File]::ReadAllText((Join-Path $d 'passwords.txt'))
T-True ($pf -match '(?m)^\S+\s+alice\s+Team-Alice-Pass-26\s') 'passwords.txt has the new password'
T-True ($pf -match '(?m)^\S+\s+bob\s+Has,Comma"Quote-99\s') 'a password with a comma or quote is written as it is'
T-HasNot $pf 'picky' 'a failed change is not in passwords.txt'
T-HasNot $pf 'mark.jacobs' 'an excluded account is not in passwords.txt'
T-True (-not (Test-Path -LiteralPath (Join-Path $d 'pending-password.txt'))) 'no pending file after a normal run'
T-Has (Row1 $d 'alice').note 'new password tested' 'each change is tested with a logon check'
$log = [IO.File]::ReadAllText(@(Get-ChildItem -LiteralPath $out -Filter 'WN-20_*.log' | Sort-Object Name)[-1].FullName)
T-HasNot $log 'Team-Alice-Pass-26' 'no password in the log'
T-HasNot $r.Text 'Team-Alice-Pass-26' 'no password on screen'

T-Start 'random passwords, -Users, -Include switches, -Print'
Reset
$r = Run @('-Out', $out, '-Apply', '-Protected', $prot, '-Users', 'svc_sql,olduser,bob', '-IncludeServices', '-IncludeDisabled', '-Print', '-Length', '20')
T-Eq $r.Code 0 'exits 0'
T-Eq (SetPw 'alice') '' 'not in -Users: untouched'
T-Eq ("" + (SetPw 'svc_sql')).Length 20 '-IncludeServices: service account changed, random password of -Length'
T-True ((SetPw 'olduser') -ne '') '-IncludeDisabled: disabled account changed'
T-True ((SetPw 'bob') -match '[A-Z]' -and (SetPw 'bob') -match '[a-z]' -and (SetPw 'bob') -match '[0-9]') 'random passwords meet Windows complexity'
T-Has $r.Text (SetPw 'bob') '-Print shows the passwords at the end'
$r2 = Run @('-Out', $out, '-Apply', '-Protected', $prot, '-Users', $me, '-IncludeMe')
T-True ((SetPw $me) -ne '') '-IncludeMe changes the running account'

T-Start 'domain controller'
Reset
[IO.File]::WriteAllText((Join-Path $fake 'is-dc'), '')
[IO.File]::AppendAllText((Join-Path $fake 'accounts.csv'), "krbtgt,domain,S-1-5-21-1-2-3-502,True,`r`n")
$r = Run @('-Out', $out, '-Apply', '-Protected', $prot, '-IncludeDisabled')
T-Has $r.Text 'domain accounts (this is a domain controller)' 'says it changes domain accounts'
T-Eq (SetPw 'krbtgt') '' 'krbtgt is never changed, even with -IncludeDisabled'
T-Has (Row1 $r.Dir 'krbtgt').note 'WN-22' 'and points to WN-22'
Remove-Item -LiteralPath (Join-Path $fake 'is-dc') -Force

T-Start 'stopped in the middle: the new password is not lost'
Reset
[IO.File]::WriteAllLines((Join-Path $fake 'fail.csv'), [string[]]@('name,reason'))
# A change that hangs: the stand-in waits when the account is "slow".
$env:BT_WN20_SLOW = 'alice'
$all = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $wn20, '-Out', $out, '-Apply', '-Protected', $prot, '-Users', 'alice')
$p = Start-Process -FilePath $psExe -ArgumentList $all -PassThru -RedirectStandardOutput (Join-Path $tmp "slow.out") -RedirectStandardError (Join-Path $tmp "slow.err")
Start-Sleep -Seconds 6
Stop-Process -Id $p.Id -Force
Remove-Item Env:\BT_WN20_SLOW
$pend = @(Get-ChildItem -LiteralPath $out -Recurse -Filter 'pending-password.txt' | Sort-Object LastWriteTime)
T-True ($pend.Count -ge 1) 'pending-password.txt is left behind when the script is killed mid-change'
if ($pend.Count -ge 1) { T-True ([IO.File]::ReadAllText($pend[-1].FullName) -match '(?m)^\S+\s+alice\s') 'and it names the account' }

T-Start 'the look and the questions'
Reset
$o7 = Join-Path $tmp 'out7'
$r = Run @('-Out', $o7, '-Protected', $prot, '-Users', 'alice', '-Batch')
T-Has $r.Text 'WN-20 Windows password rotation | host' 'the title line'
T-Has $r.Text '==========[ 1/4  accounts' 'numbered headers'
T-Has $r.Text '[~] alice' 'the planned change is shown'
T-Has $r.Text '==========[ 3/4  dry run: nothing is changed ]==========' '-Batch without -Apply: a dry run'
T-True ($r.Dir -match 'passwords-1$') 'a numbered folder passwords-1'
T-True (@(Get-ChildItem -LiteralPath $r.Dir -Recurse -Filter '*.csv').Count -eq 0) 'no CSV in the results'
# s: typed twice (a mismatch first), then apply: yes.
Reset
$env:BT_TEST_ANSWERS = 's;Typed-Pass-1234;Other-Pass-9999;Typed-Pass-1234;Typed-Pass-1234;y'
$r = Run @('-Out', $o7, '-Protected', $prot, '-Users', 'alice')
Remove-Item Env:\BT_TEST_ANSWERS
T-Has $r.Text '[?] alice (local): new password?' 'each account is asked'
T-Has $r.Text 'The two did not match: type it again' 'a mismatch is asked again'
T-Has $r.Text '[?] Apply these 1 change(s)?' 'then: apply?'
T-Eq (SetPw 'alice') 'Typed-Pass-1234' 's: the typed password is set'
T-HasNot $r.Text 'Typed-Pass-1234' 'and it is never shown'
T-HasNot ([IO.File]::ReadAllText((Join-Path $r.Dir 'output.txt'))) 'Typed-Pass-1234' 'nor in output.txt'
# k: keep - nothing to apply.
Reset
$env:BT_TEST_ANSWERS = 'k'
$r = Run @('-Out', $o7, '-Protected', $prot, '-Users', 'alice')
Remove-Item Env:\BT_TEST_ANSWERS
T-Eq (Act $r.Dir 'alice') 'skipped' 'k: kept'
T-True ($null -eq (SetPw 'alice')) 'and not changed'
# r, then apply: no.
Reset
$env:BT_TEST_ANSWERS = 'r;n'
$r = Run @('-Out', $o7, '-Protected', $prot, '-Users', 'alice')
Remove-Item Env:\BT_TEST_ANSWERS
T-Eq (Act $r.Dir 'alice') 'would change' 'apply: no is a dry run'
T-True ($null -eq (SetPw 'alice')) 'nothing changed'

T-Start 'many accounts: one question first'
Reset
$acf = Join-Path $fake 'accounts.csv'; $acSave = [IO.File]::ReadAllText($acf)
Add-Content -LiteralPath $acf -Value @('extra1,local,S-1-5-21-1-2-3-1101,False,', 'extra2,local,S-1-5-21-1-2-3-1102,False,', 'extra3,local,S-1-5-21-1-2-3-1103,False,')
$env:BT_TEST_ANSWERS = 'n'
$r = Run @('-Out', $o7, '-Protected', $prot)
Remove-Item Env:\BT_TEST_ANSWERS
$cnt = @(Rows $r.Dir | Where-Object { $_.action -eq 'would change' }).Count
if ($cnt -gt 5) {
    T-Has $r.Text ('[?] ' + $cnt + ' accounts get a new password. Go through them one by one?') 'more than 5: asked once first'
    T-HasNot $r.Text 'new password?' 'Enter = random for all: no question per account'
} else { T-True $false ('only ' + $cnt + ' accounts: the test needs more than 5') }
[IO.File]::WriteAllText($acf, $acSave)

Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
exit 0
