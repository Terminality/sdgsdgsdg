# =============================================================================
# Tests for WN-50 Windows service recovery.
#   pwsh -NoProfile -File tests/wn50.Tests.ps1
#
# Stand-in state ($env:BT_WN50_FAKE): services.csv, netstat.txt,
# processes.csv, fwrules.csv, iis.csv, disk.txt.  A broken web box: IIS
# disabled and stopped, a firewall rule blocking 80, a stopped app pool,
# MySQL stopped with a program from C:\Users\Public on its port, the event
# log stopped, a nearly full disk.  Checks: each problem found, the fixes
# and their defaults, a dry run changes nothing, -Apply fixes and checks
# again, revert.ps1, an XAMPP box (Apache on 80, IIS not in use), -Watch
# with -AutoRestart, -Services, the questions.
# =============================================================================
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
$wn50 = Join-Path (Join-Path (Join-Path $root 'roles') 'windows-ad') 'WN-50-service-recovery.ps1'
$psExe = (Get-Process -Id $PID).Path
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('cctest_wn50_' + $PID)
$out = Join-Path $tmp 'out'
$fake = Join-Path $tmp 'state'
New-Item -ItemType Directory -Path $fake -Force | Out-Null
$env:BT_SKIP_VERIFY = '1'; $env:BT_WN50_FAKE = $fake; $env:BT_TEST_BOX_GUESS = 'web|IIS is installed (W3SVC)'
$script:pass = 0; $script:fail = 0
function T-Start($t) { Write-Host "  -- $t" }
function T-Eq($got, $want, $label) { if ("$got" -ceq "$want") { $script:pass++ } else { $script:fail++; Write-Host "     FAIL: $label"; Write-Host "           got [$got], wanted [$want]" } }
function T-True($cond, $label) { if ($cond) { $script:pass++ } else { $script:fail++; Write-Host "     FAIL: $label" } }
function T-Has($text, $needle, $label) { T-True ("$text".Contains($needle)) "$label (missing [$needle])" }
function T-HasNot($text, $needle, $label) { T-True (-not "$text".Contains($needle)) "$label (found [$needle])" }
function Run([string[]]$a) {
    $all = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $wn50) + @($a)
    $text = (& $psExe @all 2>&1 | Out-String)
    $dir = ''; if ($text -match 'All results: (\S+)') { $dir = $matches[1].Trim() }
    return @{ Code = $LASTEXITCODE; Text = $text; Dir = $dir }
}
function W([string]$n, [string[]]$rows) { [IO.File]::WriteAllLines((Join-Path $fake $n), [string[]]$rows) }
function Cell([string]$n, [string]$keyCol, [string]$key, [string]$col) { foreach ($r in @(Import-Csv -LiteralPath (Join-Path $fake $n))) { if ($r.$keyCol -eq $key) { return $r.$col } }; return '(none)' }
function NetHas([string]$port) { return (@([IO.File]::ReadAllLines((Join-Path $fake 'netstat.txt')) | Where-Object { $_ -match (':' + $port + '\s') }).Count -gt 0) }
function Plant {
    W 'services.csv' @('name,display,state,startmode,path,recovery',
        'W3SVC,World Wide Web Publishing Service,Stopped,Disabled,C:\Windows\system32\svchost.exe -k iissvcs,',
        'WAS,Windows Process Activation Service,Running,Auto,C:\Windows\system32\svchost.exe -k iissvcs,restart',
        'MySQL80,MySQL80,Stopped,Auto,"""C:\Program Files\MySQL\bin\mysqld.exe"" --defaults-file=my.ini MySQL80",',
        'TermService,Remote Desktop Services,Running,Manual,C:\Windows\System32\svchost.exe -k NetworkService,',
        'EventLog,Windows Event Log,Stopped,Auto,C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted,',
        'Spooler,Print Spooler,Running,Auto,C:\Windows\System32\spoolsv.exe,')
    W 'netstat.txt' @('  TCP    0.0.0.0:3389    0.0.0.0:0    LISTENING    1000', '  TCP    0.0.0.0:3306    0.0.0.0:0    LISTENING    666', '  TCP    10.0.0.5:50000    10.0.0.9:3306    ESTABLISHED    2000')
    W 'processes.csv' @('pid,name,path', '1000,svchost.exe,C:\Windows\System32\svchost.exe', '666,nc.exe,C:\Users\Public\nc.exe')
    W 'fwrules.csv' @('name,enabled,action,dir,protocol,ports', 'Block web,True,Block,In,TCP,"80,8080"', 'Block old,False,Block,In,TCP,3389', 'Allow RDP,True,Allow,In,TCP,3389')
    W 'iis.csv' @('kind,name,state', 'site,Default Web Site,Started', 'apppool,DefaultAppPool,Stopped')
    W 'disk.txt' @('5')
}
$prot = Join-Path $tmp 'protected.txt'
[IO.File]::WriteAllLines($prot, [string[]]@('service W3SVC food ordering site'))

T-Start 'options'
$r = Run @('-Out', $out, '-Fix', 'everything'); T-Eq $r.Code 2 'an unknown fix kind exits 2'
$r = Run @('-Out', $out, '-Box', 'mainframe'); T-Eq $r.Code 2 'an unknown box exits 2'
$r = Run @('-Out', $out, '-Watch', '2'); T-Eq $r.Code 2 '-Watch under 5 exits 2'
$r = Run @('-Out', $out, '-AutoRestart'); T-Eq $r.Code 2 '-AutoRestart without -Watch exits 2'

T-Start 'check (dry run, -Batch)'
Plant; $before = (Get-ChildItem -LiteralPath $fake | ForEach-Object { [IO.File]::ReadAllText($_.FullName) }) -join ''
$r = Run @('-Out', $out, '-Protected', $prot, '-Batch')
T-Eq $r.Code 0 'exit 0'
T-Has $r.Text 'WN-50 Windows service recovery | host' 'the title line'
T-Has $r.Text 'This box looks like: web (IIS is installed (W3SVC))' 'the box guess'
T-Has $r.Text '[?] Which box is this? (its scored services come first) [d/B/e/f/s/o] b (default)' 'the box question'
T-Has $r.Text '[?] Check which services?' 'the services question'
T-Has $r.Text '[!] W3SVC          Stopped, Disabled port 80 (protected list (scored))' 'IIS is down'
T-Has $r.Text '- disabled: it cannot start' 'disabled found'
T-Has $r.Text '- the firewall blocks port 80: rule "Block web"' 'the block rule found'
T-HasNot $r.Text 'Block old' 'a turned-off rule is ignored'
T-Has $r.Text '- IIS apppool "DefaultAppPool" is Stopped' 'the stopped app pool found'
T-Has $r.Text '- another program holds port 3306: nc.exe (pid 666, C:\Users\Public\nc.exe)' 'the program on the MySQL port'
T-Has $r.Text '[ok] WAS ' 'WAS is up'
T-Has $r.Text '[ok] TermService    running port 3389' 'RDP is up'
T-Has $r.Text '[!] EventLog' 'the event log is down'
T-HasNot $r.Text 'Spooler' 'a service that is not known is not checked'
T-Has $r.Text 'the system drive has 5% free' 'the full disk'
T-Has $r.Text '[?] [firewall] turn off the firewall rule "Block web" (it blocks port 80)? [Y/n] y (default)' 'firewall fix default yes'
T-Has $r.Text '[?] [kill] stop nc.exe (pid 666) so MySQL80 gets port 3306? [Y/n] y (default)' 'kill default yes for a program from a user folder'
T-Has $r.Text '[?] [enable] set W3SVC to start at boot (Automatic)? [Y/n] y (default)' 'enable'
T-Has $r.Text '[?] [pool] start the IIS apppool "DefaultAppPool"? [Y/n] y (default)' 'the app pool'
T-Has $r.Text '3 services do not restart by themselves when they crash (W3SVC MySQL80 TermService)' 'restart-on-crash asked once'
T-Has $r.Text 'Dry run: nothing was changed' 'a dry run'
$after = (Get-ChildItem -LiteralPath $fake | ForEach-Object { [IO.File]::ReadAllText($_.FullName) }) -join ''
T-Eq $after $before 'and nothing changed'
T-True ($r.Dir -match 'recovery-\d+$') 'a numbered recovery-N folder'
T-True (Test-Path -LiteralPath (Join-Path $r.Dir 'status.txt')) 'status.txt written'
T-True (@(Get-ChildItem -LiteralPath $r.Dir -Recurse -Filter '*.csv').Count -eq 0) 'no CSV in the results'

T-Start 'apply the defaults, check again, revert'
Plant
$r = Run @('-Out', $out, '-Protected', $prot, '-Batch', '-Apply')
T-Eq $r.Code 0 'exit 0'
T-Eq (Cell 'services.csv' 'name' 'W3SVC' 'state') 'Running' 'IIS started'
T-Eq (Cell 'services.csv' 'name' 'W3SVC' 'startmode') 'Auto' 'and set to start at boot'
T-Eq (Cell 'fwrules.csv' 'name' 'Block web' 'enabled') 'False' 'the block rule is off'
T-Eq (Cell 'iis.csv' 'name' 'DefaultAppPool' 'state') 'Started' 'the app pool started'
T-Eq (Cell 'services.csv' 'name' 'MySQL80' 'state') 'Running' 'MySQL started'
T-True (-not (@([IO.File]::ReadAllLines((Join-Path $fake 'netstat.txt')) | Where-Object { $_ -match '\s666$' }).Count)) 'the program on its port stopped'
T-Eq (Cell 'services.csv' 'name' 'EventLog' 'state') 'Running' 'the event log started'
T-Eq (Cell 'services.csv' 'name' 'W3SVC' 'recovery') 'restart' 'restart on crash set'
T-Eq (Cell 'services.csv' 'name' 'Spooler' 'state') 'Running' 'Spooler not touched'
T-Has $r.Text '[ok] W3SVC is up' 'checked again: IIS up'
T-Has $r.Text '[ok] MySQL80 is up' 'checked again: MySQL up'
T-Has $r.Text 'Fixes: ' 'the fixes counted'
T-HasNot $r.Text 'FAILED' 'nothing failed'
& $psExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $r.Dir 'revert.ps1') -Force 2>&1 | Out-Null
T-Eq (Cell 'services.csv' 'name' 'W3SVC' 'startmode') 'Disabled' 'revert.ps1: start mode back'
T-Eq (Cell 'fwrules.csv' 'name' 'Block web' 'enabled') 'True' 'revert.ps1: the rule back'
T-Eq (Cell 'iis.csv' 'name' 'DefaultAppPool' 'state') 'Stopped' 'revert.ps1: the pool back'

T-Start 'an XAMPP box: Apache serves 80, IIS is not the one in use'
Plant
W 'services.csv' @('name,display,state,startmode,path,recovery',
    'W3SVC,World Wide Web Publishing Service,Stopped,Manual,C:\Windows\system32\svchost.exe -k iissvcs,',
    'Apache2.4,Apache2.4,Running,Auto,"""C:\xampp\apache\bin\httpd.exe"" -k runservice",restart')
W 'netstat.txt' @('  TCP    0.0.0.0:80    0.0.0.0:0    LISTENING    3000')
W 'processes.csv' @('pid,name,path', '3000,httpd.exe,C:\xampp\apache\bin\httpd.exe')
W 'fwrules.csv' @('name,enabled,action,dir,protocol,ports')
W 'iis.csv' @('kind,name,state')
$r = Run @('-Out', $out, '-Protected', $prot, '-Batch', '-Box', 'web')
T-Has $r.Text 'port 80 is served by Apache2.4 (httpd.exe): W3SVC is not the one in use here' 'reported'
T-HasNot $r.Text 'start W3SVC' 'IIS is not started'
T-HasNot $r.Text 'stop httpd.exe' 'Apache is not offered for stopping'
T-Has $r.Text '[ok] Apache2.4' 'Apache is up'

T-Start '-Watch with -AutoRestart'
Plant
$r = Run @('-Out', $out, '-Protected', $prot, '-Batch', '-Apply', '-Services', 'EventLog', '-Watch', '5', '-WatchCount', '2', '-AutoRestart')
T-Eq $r.Code 0 'exit 0'
T-Has $r.Text 'EventLog       DOWN (Stopped)' 'went down'
T-Has $r.Text '[+] started EventLog' 'started'
T-Has $r.Text 'EventLog       UP' 'and back up'
T-True (Test-Path -LiteralPath (Join-Path $r.Dir 'watch.txt')) 'watch.txt written'
T-Eq (Cell 'services.csv' 'name' 'EventLog' 'state') 'Running' 'it runs'

T-Start '-Services and the questions'
Plant
$r = Run @('-Out', $out, '-Protected', $prot, '-Batch', '-Services', 'MySQL80,nosuch')
T-Has $r.Text 'nosuch: no such service on this box' 'an unknown name is reported'
T-HasNot $r.Text '[!] W3SVC' '-Services: only those'
T-HasNot $r.Text 'Check which services?' '-Services answers the question'
# box b; services s (scored: W3SVC MySQL80 WAS); W3SVC: firewall y, enable y, start y, pool n, recovery n; MySQL80: kill y, start y, recovery n; apply y
$env:BT_TEST_ANSWERS = 'b;s;y;y;y;n;n;y;y;n;y'
$r = Run @('-Out', $out, '-Protected', $prot)
Remove-Item Env:\BT_TEST_ANSWERS
T-Has $r.Text '[y] yes, do it' 'each fix lists its answers'
T-HasNot $r.Text '[!] EventLog' 's: only the scored ones'
T-Eq (Cell 'services.csv' 'name' 'W3SVC' 'state') 'Running' 'y: IIS started'
T-Eq (Cell 'iis.csv' 'name' 'DefaultAppPool' 'state') 'Stopped' 'n: the pool left'
T-Eq (Cell 'services.csv' 'name' 'MySQL80' 'state') 'Running' 'y: MySQL started'
T-Eq (Cell 'services.csv' 'name' 'MySQL80' 'recovery') '' 'n: no restart on crash'
T-Eq (Cell 'services.csv' 'name' 'EventLog' 'state') 'Stopped' 'the event log not touched'
$r = Run @('-Out', $out, '-Protected', $prot, '-Batch', '-Services', 'W3SVC', '-Fix', 'pool')
T-Has $r.Text '[~] start the IIS apppool' '-Fix pool: chosen without a question'

Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
exit 0
