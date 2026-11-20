# =============================================================================
# Tests for WN-23 Account lockdown (AD).
#   pwsh -NoProfile -File tests/wn23.Tests.ps1
#
# Stand-in AD data ($env:BT_WN23_FAKE): users.csv, groups.csv and
# computers.csv with planted problems - an unknown Domain Admin made an hour
# ago, an account without Kerberos pre-authentication, one with "password not
# required", a user trusted for delegation, an SPN account, the Guest account
# enabled, a delegated computer, an old krbtgt password - beside the built-in
# Administrator, the running account and a protected account, which must never
# be touched.  Checks: each finding; the defaults; a dry run changes nothing;
# -Apply changes exactly what was chosen; the undo puts it back; the questions.
# Nothing outside the temp folder is touched.
# =============================================================================
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
$wn23 = Join-Path (Join-Path (Join-Path $root 'roles') 'windows-ad') 'WN-23-ad-lockdown.ps1'
$psExe = (Get-Process -Id $PID).Path
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('cctest_wn23_' + $PID)
$out = Join-Path $tmp 'out'
$fake = Join-Path $tmp 'ad'
New-Item -ItemType Directory -Path $fake -Force | Out-Null
$env:BT_SKIP_VERIFY = '1'; $env:BT_WN23_FAKE = $fake
$script:pass = 0; $script:fail = 0
function T-Start($t) { Write-Host "  -- $t" }
function T-Eq($got, $want, $label) { if ("$got" -ceq "$want") { $script:pass++ } else { $script:fail++; Write-Host "     FAIL: $label"; Write-Host "           got [$got], wanted [$want]" } }
function T-True($cond, $label) { if ($cond) { $script:pass++ } else { $script:fail++; Write-Host "     FAIL: $label" } }
function T-Has($text, $needle, $label) { T-True ("$text".Contains($needle)) "$label (missing [$needle])" }
function T-HasNot($text, $needle, $label) { T-True (-not "$text".Contains($needle)) "$label (found [$needle])" }
function Run([string[]]$a) {
    $all = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $wn23) + @($a)
    $text = (& $psExe @all 2>&1 | Out-String)
    $dir = ''; if ($text -match 'All results: (\S+)') { $dir = $matches[1].Trim() }
    return @{ Code = $LASTEXITCODE; Text = $text; Dir = $dir }
}
function Uac($name) { foreach ($r in @(Import-Csv -LiteralPath (Join-Path $fake 'users.csv'))) { if ($r.name -eq $name) { return [int]$r.uac } }; return -1 }
function InGroup($g, $m) { return (@(Import-Csv -LiteralPath (Join-Path $fake 'groups.csv') | Where-Object { $_.group -eq $g -and $_.member -eq $m }).Count -gt 0) }
function Snap { return (([IO.File]::ReadAllText((Join-Path $fake 'users.csv'))) + ([IO.File]::ReadAllText((Join-Path $fake 'groups.csv')))) }

$me = [Environment]::UserName; if (-not $me) { $me = $env:USERNAME }; if (-not $me) { $me = $env:USER }
$hourAgo = [DateTime]::UtcNow.AddHours(-1).ToString('yyyy-MM-ddTHH:mm:ssZ')
$old = '2024-01-01T10:00:00Z'
function Plant {
    [IO.File]::WriteAllLines((Join-Path $fake 'users.csv'), [string[]]@(
        'name,sid,uac,created,pwdlastset,spn,dn',
        "Administrator,S-1-5-21-9-500,66048,$old,$old,,CN=Administrator",
        "Guest,S-1-5-21-9-501,544,$old,,,CN=Guest",
        "krbtgt,S-1-5-21-9-502,514,$old,$old,,CN=krbtgt",
        "$me,S-1-5-21-9-1100,512,$old,$old,,CN=$me",
        "blueadmin,S-1-5-21-9-1101,512,$old,$old,,CN=blueadmin",
        "sysupd,S-1-5-21-9-1102,512,$hourAgo,$hourAgo,,CN=sysupd",
        "roastme,S-1-5-21-9-1103,4194816,$old,$old,,CN=roastme",
        "nopass,S-1-5-21-9-1104,544,$old,$old,,CN=nopass",
        "delegated,S-1-5-21-9-1105,524800,$old,$old,,CN=delegated",
        "svc_sql,S-1-5-21-9-1106,66048,$old,$old,MSSQLSvc/db.corp.local:1433,CN=svc_sql",
        "scorer,S-1-5-21-9-1107,4194816,$old,$old,,CN=scorer",
        "alice,S-1-5-21-9-1108,512,$old,$old,,CN=alice"))
    [IO.File]::WriteAllLines((Join-Path $fake 'groups.csv'), [string[]]@(
        'group,member',
        'Domain Admins,Administrator', "Domain Admins,$me", 'Domain Admins,blueadmin', 'Domain Admins,sysupd',
        'Administrators,Domain Admins', 'Administrators,Enterprise Admins', 'Administrators,alice',
        'DnsAdmins,scorer'))
    [IO.File]::WriteAllLines((Join-Path $fake 'computers.csv'), [string[]]@('name,uac,dn', 'DC01$,532480,CN=DC01', 'APP01$,528384,CN=APP01'))
}
$prot = Join-Path $tmp 'protected.txt'
[IO.File]::WriteAllLines($prot, [string[]]@('account scorer the scoring engine logs in as this'))

T-Start 'options'
$r = Run @('-Out', $out, '-Only', 'everything'); T-Eq $r.Code 2 'an unknown part exits 2'
$r = Run @('-Out', $out, '-Hours', '0'); T-Eq $r.Code 2 '-Hours 0 exits 2'
Plant
$r = Run @('-Out', $out, '-Admins', 'blueadmn', '-Batch'); T-Eq $r.Code 2 'a misspelled -Admins name exits 2'
T-Has $r.Text 'no such account: blueadmn' 'and says which'

T-Start 'find (dry run, -Batch)'
Plant; $before = Snap
$r = Run @('-Out', $out, '-Protected', $prot, '-Batch')
T-Eq $r.Code 0 'exit 0'
T-Has $r.Text 'WN-23 Account lockdown (AD) | host' 'the title line'
T-Has $r.Text '==========[ 1/4  looking ]==========' 'numbered headers'
T-Has $r.Text 'sysupd is in Domain Admins (made 1 h ago - not named in -Admins: yours?)' 'a new Domain Admin is HIGH'
T-Has $r.Text 'roastme: no Kerberos pre-authentication' 'AS-REP roastable is HIGH'
T-Has $r.Text 'nopass: password not required' 'password not required is HIGH'
T-Has $r.Text 'delegated: trusted for unconstrained delegation' 'a delegated user is HIGH'
T-Has $r.Text 'svc_sql has an SPN (MSSQLSvc/db.corp.local:1433)' 'an SPN account is reported'
T-Has $r.Text 'the Guest account is enabled' 'Guest on is HIGH'
T-Has $r.Text 'computer APP01$ is trusted for unconstrained delegation' 'a delegated computer (not the DC) is reported'
T-HasNot $r.Text 'computer DC01$' 'the domain controller itself is not'
T-Has $r.Text 'krbtgt password is' 'the krbtgt age is shown'
T-Has $r.Text 'sysupd was made 1 h ago - a teammate, or red team?' 'a new account is listed'
T-Has $r.Text 'alice is in Administrators' 'every unexpected admin is listed'
T-HasNot $r.Text 'Domain Admins is in Administrators' 'the built-in nesting is not'
T-Has $r.Text 'scorer: no Kerberos pre-authentication: anyone can ask for a hash of its password and crack it (AS-REP roasting) - left: on the protected list' 'a protected account is shown as left, never offered'
T-HasNot $r.Text 'scorer: no Kerberos pre-authentication: anyone can ask for a hash of its password and crack it (AS-REP roasting) ->' 'and not asked'
T-HasNot $r.Text ($me + ' is in Domain Admins') 'nor the account running the script'
T-HasNot $r.Text 'Administrator is in Domain Admins' 'nor the built-in Administrator'
T-Has $r.Text 'sysupd is in Domain Admins (made 1 h ago - not named in -Admins: yours?) -> keep (default)' 'without -Admins an admin is kept by default (could be a teammate)'
T-Has $r.Text 'roastme: no Kerberos pre-authentication: anyone can ask for a hash of its password and crack it (AS-REP roasting) -> fix (default)' 'a risky flag defaults to fix'
T-Has $r.Text 'Dry run: nothing was changed' 'a dry run'
T-Eq (Snap) $before 'and nothing changed'
T-True ($r.Dir -match 'ad-lockdown-\d+$') 'a numbered folder ad-lockdown-N'
T-Has ([IO.File]::ReadAllText((Join-Path $r.Dir 'findings.txt'))) 'roastme' 'findings.txt'
T-True (@(Get-ChildItem -LiteralPath $r.Dir -Recurse -Filter '*.csv').Count -eq 0) 'no CSV in the results'

T-Start 'apply with -Admins (-Batch: the defaults)'
Plant
$env:BT_TEST_SCHTASKS = Join-Path $tmp 'schtasks0.log'
$r = Run @('-Out', $out, '-Protected', $prot, '-Batch', '-Apply', '-Admins', 'blueadmin')
Remove-Item Env:\BT_TEST_SCHTASKS
T-Eq $r.Code 0 'exit 0'
T-True (-not (InGroup 'Domain Admins' 'sysupd')) 'a Domain Admin not in -Admins is removed'
T-True (-not (InGroup 'Administrators' 'alice')) 'and from Administrators'
T-True (InGroup 'Domain Admins' 'blueadmin') 'the -Admins account stays'
T-True (InGroup 'Domain Admins' $me) 'the running account stays'
T-True (InGroup 'DnsAdmins' 'scorer') 'the protected account stays'
T-True (InGroup 'Administrators' 'Domain Admins') 'the built-in nesting stays'
T-Eq (Uac 'roastme') 512 'pre-authentication required again'
T-Eq (Uac 'nopass') 512 'password required again'
T-Eq (Uac 'delegated') 512 'delegation off'
T-Eq (Uac 'Guest') 514 'Guest: password required and disabled'
T-Eq (Uac 'sysupd') 512 'a new account is kept by default (could be a teammate)'
T-Eq (Uac 'scorer') 4194816 'a protected account is not changed'
T-Eq (Uac 'svc_sql') 66048 'an SPN account is only reported'
T-Has $r.Text '[+] remove sysupd from Domain Admins' 'each change is shown'
$u = [IO.File]::ReadAllText((Join-Path $r.Dir 'undo.txt'))
T-Has $u 'sysupd back in Domain Admins' 'each change has an undo line'
& $psExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $r.Dir 'revert.ps1') -Force 2>&1 | Out-Null
T-True (InGroup 'Domain Admins' 'sysupd') 'revert.ps1 puts the member back'
T-Eq (Uac 'roastme') 4194816 'and the flag'

T-Start 'questions on a console (test answers) and the revert timer'
Plant
$sch = Join-Path $tmp 'schtasks.log'; $env:BT_TEST_SCHTASKS = $sch
# HIGH first, then by kind and name: account flag delegated (k), nopass (f),
# then a = all the rest their default; apply: y; keep: y
$env:BT_TEST_ANSWERS = 'k;f;a;y;y'
$r = Run @('-Out', $out, '-Protected', $prot)
Remove-Item Env:\BT_TEST_ANSWERS
T-Has $r.Text '[f] fix it:' 'each finding lists its answers'
T-Has $r.Text '[?] Apply these' 'then: apply?'
T-Eq (Uac 'delegated') 524800 'k: kept'
T-Eq (Uac 'nopass') 512 'f: fixed'
T-Eq (Uac 'roastme') 512 'a: the rest take their default (fix)'
T-True (InGroup 'Domain Admins' 'sysupd') 'a: an admin without -Admins takes its default (keep)'
T-Has ([IO.File]::ReadAllText($sch)) '/SC ONCE' 'the revert timer is set'
T-Has $r.Text 'Changes kept' 'keep: y'
Remove-Item Env:\BT_TEST_SCHTASKS

T-Start '-Only and -Approved'
Plant
$ap = Join-Path $tmp 'approved.txt'; [IO.File]::WriteAllLines($ap, [string[]]@('# team', 'blueadmin', 'roastme', 'nopass', 'delegated', 'svc_sql', 'sysupd'))
$r = Run @('-Out', $out, '-Protected', $prot, '-Batch', '-Only', 'approved', '-Approved', $ap)
T-Has $r.Text 'alice is enabled but not in -Approved' 'an enabled account not approved is listed'
T-HasNot $r.Text 'roastme' '-Only approved: nothing else'
T-HasNot $r.Text 'scorer is enabled' 'a protected account is not offered'

Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
exit 0
