# =============================================================================
# Tests for WN-44 Windows change watch.
#   pwsh -NoProfile -File tests/wn44.Tests.ps1
#
# Stand-in snapshots ($env:BT_WN44_FAKE): one <section>.txt per section
# ("key|detail" lines) and events.txt ("time|kind|detail|address").  The
# test takes a baseline, plants red-team changes (an account, an admin, a
# service from Temp, the event log stopped, an encoded task, a Run value, a
# listener on 4444, the firewall off, a WMI subscription, a new page, a
# cleared log, Remote Desktop logons) and checks each alert, its level, that
# each is reported once, changes-since-baseline.txt, -Accept, -Loop/-Count,
# -AlertTo, the team addresses and the questions.
# =============================================================================
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
$wn44 = Join-Path (Join-Path (Join-Path $root 'roles') 'windows-ad') 'WN-44-change-watch.ps1'
$psExe = (Get-Process -Id $PID).Path
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('cctest_wn44_' + $PID)
$out = Join-Path $tmp 'out'
$fake = Join-Path $tmp 'state'
New-Item -ItemType Directory -Path $fake -Force | Out-Null
$env:BT_SKIP_VERIFY = '1'; $env:BT_WN44_FAKE = $fake
$script:pass = 0; $script:fail = 0
function T-Start($t) { Write-Host "  -- $t" }
function T-Eq($got, $want, $label) { if ("$got" -ceq "$want") { $script:pass++ } else { $script:fail++; Write-Host "     FAIL: $label"; Write-Host "           got [$got], wanted [$want]" } }
function T-True($cond, $label) { if ($cond) { $script:pass++ } else { $script:fail++; Write-Host "     FAIL: $label" } }
function T-Has($text, $needle, $label) { T-True ("$text".Contains($needle)) "$label (missing [$needle])" }
function T-HasNot($text, $needle, $label) { T-True (-not "$text".Contains($needle)) "$label (found [$needle])" }
function Run([string[]]$a) {
    $all = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $wn44) + @($a)
    $text = (& $psExe @all 2>&1 | Out-String)
    $dir = ''; if ($text -match 'All results: (\S+)') { $dir = $matches[1].Trim() }
    return @{ Code = $LASTEXITCODE; Text = $text; Dir = $dir }
}
function W([string]$sec, [string[]]$rows) { [IO.File]::WriteAllLines((Join-Path $fake ($sec + '.txt')), [string[]]$rows) }
function Clean {
    W 'users' @('Administrator|enabled', 'Guest|disabled', 'alice|enabled')
    W 'admins' @('Administrators: HOST\Administrator|', 'Administrators: CORP\Domain Admins|')
    W 'services' @('EventLog|Auto C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted', 'Spooler|Auto C:\Windows\System32\spoolsv.exe', 'W3SVC|Auto C:\Windows\system32\svchost.exe -k iissvcs')
    W 'running' @('EventLog|Running', 'Spooler|Running', 'W3SVC|Running')
    W 'tasks' @('\Microsoft\Windows\Defrag\ScheduledDefrag|%windir%\system32\defrag.exe -c')
    W 'runkeys' @('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SecurityHealth|C:\Windows\system32\SecurityHealthSystray.exe')
    W 'ports' @('tcp/80|System', 'tcp/3389|svchost.exe')
    W 'shares' @('Menus|C:\Shares\Menus')
    W 'security' @('firewall Domain|on', 'firewall Private|on', 'firewall Public|on', 'defender real-time|on', 'sticky keys|on (normal)')
    W 'wmi' @()
    W 'ifeo' @()
    W 'hosts' @('hosts|aaaa')
    W 'web' @('C:\inetpub\wwwroot\default.aspx|120 bytes, 2026-11-01 10:00')
    W 'events' @()
}
$prot = Join-Path $tmp 'protected.txt'
[IO.File]::WriteAllLines($prot, [string[]]@('service W3SVC food ordering site'))

T-Start 'options'
$r = Run @('-Out', $out, '-Loop', '5'); T-Eq $r.Code 2 '-Loop under 10 exits 2'
$r = Run @('-Out', $out, '-Baseline', '-UseBaseline'); T-Eq $r.Code 2 '-Baseline with -UseBaseline exits 2'

T-Start 'first run: the baseline'
Clean
$r = Run @('-Out', $out, '-Protected', $prot, '-Batch')
T-Eq $r.Code 0 'exit 0'
T-Has $r.Text 'WN-44 Windows change watch | host' 'the title line'
T-Has $r.Text 'READ-ONLY' 'read-only'
T-Has $r.Text 'No baseline yet: one is taken now.' 'no baseline yet'
T-Has $r.Text '[ok] baseline taken' 'taken'
T-Has $r.Text 'users 3' 'with counts'
T-True ($r.Dir -match 'changewatch-\d+$') 'a numbered changewatch-N folder'
$st = @(Get-ChildItem -LiteralPath $out | Where-Object { $_.PSIsContainer -and $_.Name -like 'watch-*' })[0].FullName
T-True (Test-Path -LiteralPath (Join-Path (Join-Path $st 'baseline') 'users.txt')) 'the baseline is saved'

T-Start 'red team changes'
Start-Sleep -Milliseconds 1100
$now = [DateTime]::Now
W 'users' @('Administrator|enabled', 'Guest|enabled', 'alice|enabled', 'support|enabled')
W 'admins' @('Administrators: HOST\Administrator|', 'Administrators: CORP\Domain Admins|', 'Administrators: HOST\support|')
W 'services' @('EventLog|Auto C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted', 'Spooler|Auto C:\Windows\System32\spoolsv.exe', 'W3SVC|Auto C:\Windows\system32\svchost.exe -k iissvcs', 'WinUpd|Auto C:\Windows\Temp\upd.exe')
W 'running' @('W3SVC|Running', 'WinUpd|Running')
W 'tasks' @('\Microsoft\Windows\Defrag\ScheduledDefrag|%windir%\system32\defrag.exe -c', '\Updater|powershell.exe -w hidden -enc AAAA')
W 'runkeys' @('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SecurityHealth|C:\Windows\system32\SecurityHealthSystray.exe', 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\sync|C:\Users\Public\s.exe')
W 'ports' @('tcp/3389|svchost.exe', 'tcp/4444|nc.exe')
W 'security' @('firewall Domain|on', 'firewall Private|on', 'firewall Public|off', 'defender real-time|on', 'sticky keys|on (normal)')
W 'wmi' @('CommandLineEventConsumer.Name="x"|__EventFilter.Name="x"')
W 'web' @('C:\inetpub\wwwroot\default.aspx|120 bytes, 2026-11-01 10:00', 'C:\inetpub\wwwroot\up.aspx|90 bytes, 2026-11-21 01:00')
W 'events' @(
    ($now.AddDays(-2).ToString('o') + '|cleared|an old one, before the last check|'),
    ($now.AddSeconds(2).ToString('o') + '|cleared|the Security log was cleared by support|'),
    ($now.AddSeconds(2).ToString('o') + '|rdp|Remote Desktop logon: HOST\support from 10.6.6.6|10.6.6.6'),
    ($now.AddSeconds(3).ToString('o') + '|rdp|Remote Desktop logon: HOST\support from 10.6.6.6|10.6.6.6'),
    ($now.AddSeconds(2).ToString('o') + '|rdp|Remote Desktop logon: HOST\blue from 10.0.0.5|10.0.0.5'))
$af = Join-Path $tmp 'alerts-share.txt'
$r = Run @('-Out', $out, '-Protected', $prot, '-Batch', '-Team', '10.0.0.5', '-AlertTo', $af)
T-Eq $r.Code 0 'exit 0'
T-Has $r.Text '[?] Use the baseline from' 'the baseline question'
T-Has $r.Text '[!] HIGH admins   added   Administrators: HOST\support - a new member of an admin group' 'a new admin is HIGH'
T-Has $r.Text '[*] MED  users    added   support - a new account' 'a new account is MED'
T-Has $r.Text 'users    changed Guest - an account was enabled' 'Guest enabled'
T-Has $r.Text 'HIGH services added   WinUpd - a new service from a temp or user folder' 'a service from Temp is HIGH'
T-Has $r.Text 'HIGH running  removed EventLog - stopped (a scored or security service)' 'the event log stopped is HIGH'
T-Has $r.Text 'MED  running  removed Spooler - stopped' 'another service stopped is MED'
T-HasNot $r.Text 'running  added' 'a service starting is not an alert'
T-Has $r.Text 'HIGH tasks    added   \Updater - a new task that downloads, hides' 'an encoded task is HIGH'
T-Has $r.Text 'HIGH runkeys  added' 'a Run value is HIGH'
T-Has $r.Text 'HIGH ports    added   tcp/4444 - a new listener: nc.exe (a shell or tunnel)' 'nc listening is HIGH'
T-Has $r.Text 'MED  ports    removed tcp/80 - nothing listens here any more' 'a port gone quiet is MED'
T-Has $r.Text 'HIGH security changed firewall Public - turned off' 'the firewall off is HIGH'
T-Has $r.Text 'HIGH wmi      added' 'a WMI subscription is HIGH'
T-Has $r.Text 'HIGH web      added   C:\inetpub\wwwroot\up.aspx - a new page in the site: WN-16 checks it' 'a new page is HIGH'
T-Has $r.Text 'HIGH events   cleared' 'a cleared log is HIGH'
T-HasNot $r.Text 'an old one, before the last check' 'events before the last check are not repeated'
T-Eq ([regex]::Matches($r.Text, 'from 10\.6\.6\.6').Count) 1 'a new RDP address is reported once'
T-HasNot $r.Text 'from 10.0.0.5' 'a team address is never alerted'
T-True ($r.Text.IndexOf('[!] HIGH') -lt $r.Text.IndexOf('[*] MED')) 'worst first'
T-Has $r.Text 'Alerts: 10 HIGH' 'the count'
T-True ((Test-Path -LiteralPath $af) -and ([IO.File]::ReadAllText($af).Contains('HIGH admins added'))) '-AlertTo gets a copy'
T-True (Test-Path -LiteralPath (Join-Path $r.Dir 'alerts.txt')) 'alerts.txt in the run'
T-True ([IO.File]::ReadAllText((Join-Path $st 'alerts.log')).Contains('HIGH ports added tcp/4444')) 'alerts.log kept'
T-True (@(Get-ChildItem -LiteralPath $r.Dir -Recurse -Filter '*.csv').Count -eq 0) 'no CSV in the results'

T-Start 'each change once; the full list against the baseline'
$r = Run @('-Out', $out, '-Protected', $prot, '-Batch', '-Team', '10.0.0.5')
T-Has $r.Text 'no change' 'nothing new: no alert'
T-HasNot $r.Text 'HIGH admins' 'not reported again'
$cb = [IO.File]::ReadAllText((Join-Path $st 'changes-since-baseline.txt'))
T-Has $cb 'HIGH admins   added   Administrators: HOST\support' 'changes-since-baseline.txt still lists it'

T-Start '-Accept: your own changes become the baseline'
$r = Run @('-Out', $out, '-Protected', $prot, '-Batch', '-Accept')
T-Has $r.Text '[ok] baseline taken' 'a new baseline'
W 'shares' @('Menus|C:\Shares\Menus', 'loot|C:\Users\Public')
$r = Run @('-Out', $out, '-Protected', $prot, '-Batch', '-NoEvents')
T-Has $r.Text 'MED  shares   added   loot - a new share' 'a new share'
T-HasNot $r.Text 'admins' 'the accepted changes are quiet'
$cb = [IO.File]::ReadAllText((Join-Path $st 'changes-since-baseline.txt'))
T-HasNot $cb 'support' 'the baseline moved on'
T-HasNot $r.Text 'Read the event logs too?' '-NoEvents answers the question'

T-Start '-Loop with -Count'
W 'hosts' @('hosts|bbbb')
$r = Run @('-Out', $out, '-Protected', $prot, '-Batch', '-NoEvents', '-Loop', '10', '-Count', '2')
T-Has $r.Text 'checking every 10 s' 'loops'
T-Eq ([regex]::Matches($r.Text, 'hosts    changed').Count) 1 'the change once'
T-Has $r.Text 'checks: 2' 'two checks'

T-Start 'the questions'
W 'ifeo' @('notepad.exe|C:\Windows\Temp\np.exe')
# use the baseline: y; how often: 0; events: n
$env:BT_TEST_ANSWERS = 'y;0;n'
$r = Run @('-Out', $out, '-Protected', $prot)
Remove-Item Env:\BT_TEST_ANSWERS
T-Has $r.Text 'How often should it check?' 'the loop question'
T-Has $r.Text 'HIGH ifeo     added   notepad.exe' 'checked once'
T-HasNot $r.Text 'team''s addresses' 'no events: no team question'
$env:BT_TEST_ANSWERS = 'n;0;y;10.0.0.7 10.0.0.8'
$r = Run @('-Out', $out, '-Protected', $prot)
Remove-Item Env:\BT_TEST_ANSWERS
T-Has $r.Text '[ok] baseline taken' 'n: a new baseline'
T-Eq ([IO.File]::ReadAllText((Join-Path $st 'team.txt'))) '10.0.0.7 10.0.0.8' 'the team addresses are kept for next time'

Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
exit 0
