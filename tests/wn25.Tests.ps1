# =============================================================================
# Tests for WN-25 Windows firewall.
#   pwsh -NoProfile -File tests/wn25.Tests.ps1
#
# Everything the script reads or changes goes through $env:CCDC_WN25_FAKE: a
# folder of stand-in state (profiles.csv, rules.csv, netstat.txt,
# processes.csv, logging.txt, task.txt for the rollback task).  The tests
# check the plan, apply it, fire the rollback, keep a change, -Undo, -Remove
# and -Strict, and compare the state with how it started.  Nothing real is
# read or changed.
# =============================================================================
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
$wn25 = Join-Path (Join-Path (Join-Path $root 'roles') 'windows-ad') 'WN-25-firewall.ps1'
$psExe = (Get-Process -Id $PID).Path
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('cctest_wn25_' + $PID)
$out = Join-Path $tmp 'out'; $fake = Join-Path $tmp 'fake'
$env:CCDC_SKIP_VERIFY = '1'; $env:CCDC_WN25_FAKE = $fake
$script:pass = 0; $script:fail = 0
function T-Start($t) { Write-Host "  -- $t" }
function T-Eq($got, $want, $label) { if ("$got" -ceq "$want") { $script:pass++ } else { $script:fail++; Write-Host "     FAIL: $label"; Write-Host "           got [$got], wanted [$want]" } }
function T-True($cond, $label) { if ($cond) { $script:pass++ } else { $script:fail++; Write-Host "     FAIL: $label" } }
function T-Has($text, $needle, $label) { T-True ("$text".Contains($needle)) "$label (missing [$needle])" }
function T-HasNot($text, $needle, $label) { T-True (-not "$text".Contains($needle)) "$label (found [$needle])" }
function Run([string[]]$a) {
    $all = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $wn25) + @($a)
    $text = (& $psExe @all 2>&1 | Out-String)
    $dir = ''; if ($text -match 'All results: (\S+)') { $dir = $matches[1].Trim() }
    return @{ Code = $LASTEXITCODE; Text = $text; Dir = $dir }
}
function RunFile($f) { return (& $psExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $f 2>&1 | Out-String) }
function Rules { return @(Import-Csv -LiteralPath (Join-Path $fake 'rules.csv')) }
function Rule($name) { return @(Rules | Where-Object { $_.name -eq $name }) }
function Enabled($name) { $r = @(Rule $name); if ($r.Count -eq 0) { return '(none)' }; return $r[0].enabled }
function Snap {
    $s = @()
    foreach ($f in @(Get-ChildItem -LiteralPath $fake | Where-Object { -not $_.PSIsContainer } | Sort-Object Name)) {
        $lines = @([IO.File]::ReadAllLines($f.FullName))
        if ($f.Extension -eq '.csv') { $lines = @($lines | ConvertFrom-Csv | ForEach-Object { (@($_.PSObject.Properties | Sort-Object Name | ForEach-Object { [string]$_.Value })) -join '|' } | Sort-Object) }
        $s += ('== ' + $f.Name); $s += $lines
    }
    return ($s -join "`n")
}
function Plant {
    if (Test-Path -LiteralPath $fake) { Remove-Item -LiteralPath $fake -Recurse -Force }
    New-Item -ItemType Directory -Path $fake -Force | Out-Null
    [IO.File]::WriteAllLines((Join-Path $fake 'profiles.csv'), [string[]]@('name,on,blockin', 'Domain,False,True', 'Private,True,False', 'Public,True,True'))
    [IO.File]::WriteAllLines((Join-Path $fake 'rules.csv'), [string[]]@(
        'name,enabled,protocol,lports,raddr,app,svc,group,pkg,laddr,iface,icmp',
        'Allow All,True,256,*,*,,,,,*,All,',
        'backdoor,True,6,4444,*,C:\Windows\Temp\nc.exe,,,,*,All,',
        'helper,True,6,7777,*,C:\Users\Public\h.exe,,,,*,All,',
        'odd port,True,6,31337,*,,,,,*,All,',
        'Remote Desktop - User Mode (TCP-In),True,6,3389,*,%SystemRoot%\system32\svchost.exe,termservice,"@FirewallAPI.dll,-28752",,*,All,',
        '@{Microsoft.LockApp_10.0},True,256,*,*,,,,S-1-15-2-1,*,All,',
        'Tailscale-In,True,256,*,*,,,,,100.105.236.63,All,',
        'SQL Server,True,6,1433,*,C:\Program Files\Microsoft SQL Server\sqlservr.exe,,,,*,All,',
        'Active Directory Domain Services (LDAP-In),True,6,389,*,%systemroot%\System32\lsass.exe,,"@%systemroot%\system32\NTDSMSG.DLL,-1000",,*,All,',
        'Old allow all,False,256,*,*,,,,,*,All,'))
    [IO.File]::WriteAllLines((Join-Path $fake 'netstat.txt'), [string[]]@(
        '  Proto  Local Address          Foreign Address        State           PID',
        '  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4',
        '  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4',
        '  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       1200',
        '  TCP    0.0.0.0:4444           0.0.0.0:0              LISTENING       3300',
        '  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4',
        '  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       3400',
        '  TCP    0.0.0.0:9090           0.0.0.0:0              LISTENING       3500',
        '  TCP    127.0.0.1:5432         0.0.0.0:0              LISTENING       3600',
        '  TCP    0.0.0.0:50123          0.0.0.0:0              LISTENING       700',
        '  TCP    10.0.0.50:51000        10.0.0.5:445           ESTABLISHED     4',
        '  TCP    [::]:80                [::]:0                 LISTENING       4',
        '  UDP    0.0.0.0:53             *:*                                    2100',
        '  UDP    0.0.0.0:61000          *:*                                    2100'))
    [IO.File]::WriteAllLines((Join-Path $fake 'processes.csv'), [string[]]@('pid,name,path',
        '4,System,', '1200,svchost.exe,C:\Windows\System32\svchost.exe', '3300,nc.exe,C:\Windows\Temp\nc.exe',
        '3400,updater.exe,C:\Users\bob\AppData\Local\updater.exe', '3500,powershell.exe,C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
        '3600,postgres.exe,C:\Program Files\PostgreSQL\bin\postgres.exe', '700,lsass.exe,C:\Windows\System32\lsass.exe', '2100,dns.exe,C:\Windows\System32\dns.exe'))
}
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$prot = Join-Path $tmp 'protected.csv'
[IO.File]::WriteAllLines($prot, [string[]]@('type,value,note', 'port,25/tcp,mail (scored; down right now)', 'port,5985/tcp,scoring uses WinRM', 'host,10.0.0.5,scoring engine', 'host,scorebox,a name'))

T-Start 'options'
$r = Run @('-Out', $out, '-Allow', '80/xyz'); T-Eq $r.Code 2 'a bad port exits 2'
$r = Run @('-Out', $out, '-AdminFrom', '10.0.0.300'); T-Eq $r.Code 2 'a bad address exits 2'
$r = Run @('-Out', $out, '-ConfirmMinutes', '1'); T-Eq $r.Code 2 '-ConfirmMinutes 1 exits 2'
Plant
$r = Run @('-Out', $out, '-Apply'); T-Eq $r.Code 3 '-Apply without a protected list is refused'

T-Start 'dry run: the plan, nothing changed'
Plant; $start = Snap
$r = Run @('-Out', $out, '-Protected', $prot, '-Allow', '8443/tcp', '-Exclude', '5985/tcp,9999/tcp', '-AdminFrom', '10.0.0.0/24')
T-Eq $r.Code 0 'exits 0'
T-Eq (Snap) $start 'nothing changed'
$plan = [IO.File]::ReadAllText((Join-Path $r.Dir 'plan.csv'))
T-Has $plan '"CCDC allow 25/tcp","TCP","25","","protected list (scored)"' 'a protected port is opened even though nothing listens now'
T-Has $plan '"CCDC allow 80/tcp"' 'listening web port opened'
T-Has $plan '"CCDC allow 3389/tcp"' 'RDP opened (listening)'
T-Has $plan '"CCDC allow 53/udp"' 'listening UDP port opened'
T-Has $plan '"CCDC allow 8443/tcp","TCP","8443","","-Allow"' '-Allow opened'
T-Has $plan '"CCDC allow 5985/tcp","TCP","5985","","protected list (scored)' 'protected wins over -Exclude'
T-Has $r.Text 'both protected and in -Exclude' 'and that is warned about'
T-Has $plan '"CCDC allow admin and scoring hosts","ANY","","10.0.0.5,10.0.0.0/24"' 'protected hosts and -AdminFrom get everything'
T-HasNot $plan 'scorebox' 'a host NAME is not used as an address'
T-Has $plan '"CCDC allow ping","ICMP"' 'ping allowed'
T-HasNot $plan '4444' 'nc listener not opened'
T-HasNot $plan '8080' 'listener in AppData not opened'
T-HasNot $plan '9090' 'PowerShell listener not opened'
T-HasNot $plan '5432' 'loopback-only listener not opened'
T-HasNot $plan '50123' 'dynamic port not opened'
T-HasNot $plan '61000' 'dynamic UDP port not opened'
$na = [IO.File]::ReadAllText((Join-Path $r.Dir 'not-allowed.csv'))
T-Has $na 'nc.exe is listening: a shell or tunnel' 'the reason for 4444 is written'
T-Has $na 'unusual folder' 'the reason for 8080 is written'
T-Has $r.Text 'NOT opened, though something listens' 'the summary shows what is not opened'
T-Has $r.Text 'Allow All: allows every port, protocol and address' 'allow-all rule would be turned off'
T-Has $r.Text 'backdoor: allows a shell or tunnel in' 'rule for nc would be turned off'
T-Has $r.Text 'helper: allows a program in an unusual folder' 'rule for a program in Users\Public would be turned off'
T-Has $r.Text 'odd port: opens backdoor port 31337' 'rule opening a backdoor port would be turned off'
T-HasNot $r.Text 'Microsoft.LockApp_10.0}: ' 'an app-package rule is not "allow all"'
T-HasNot $r.Text 'Tailscale-In: ' 'a rule limited to one local address is not "allow all"'
T-HasNot $r.Text 'SQL Server: ' 'a normal program rule is kept'
T-Has $r.Text 'Dry run: nothing was changed' 'says it is a dry run'

T-Start 'apply'
Plant; $start = Snap
$r = Run @('-Out', $out, '-Apply', '-Protected', $prot, '-AdminFrom', '10.0.0.6')
$run1 = $r.Dir
T-Eq $r.Code 0 'exits 0'
T-Eq (@(Import-Csv -LiteralPath (Join-Path $fake 'profiles.csv') | Where-Object { $_.on -eq 'True' -and $_.blockin -eq 'True' }).Count) 3 'all three profiles on and blocking inbound'
T-Eq (Enabled 'CCDC allow 25/tcp') 'True' 'scored port rule added'
T-Eq (Rule 'CCDC allow 25/tcp')[0].group 'CCDC' 'in group CCDC'
T-Eq (Rule 'CCDC allow admin and scoring hosts')[0].raddr '10.0.0.5,10.0.0.6' 'admin hosts rule'
T-Eq (Enabled 'Allow All') 'False' 'allow-all rule turned off'
T-Eq (Enabled 'backdoor') 'False' 'nc rule turned off'
T-Eq (Enabled 'odd port') 'False' 'backdoor-port rule turned off'
T-Eq (Enabled 'Remote Desktop - User Mode (TCP-In)') 'True' 'normal Windows rule kept'
T-Eq (Rule 'Remote Desktop - User Mode (TCP-In)')[0].group '@FirewallAPI.dll,-28752' '(fixture check: the group with a comma reads as one field)'
T-Eq (Enabled '@{Microsoft.LockApp_10.0}') 'True' 'app-package rule kept'
T-Eq (Enabled 'SQL Server') 'True' 'program rule kept'
T-True (Test-Path -LiteralPath (Join-Path $fake 'logging.txt')) 'dropped connections logged'
T-True (Test-Path -LiteralPath (Join-Path $fake 'task.txt')) 'rollback task created'
T-True (Test-Path -LiteralPath (Join-Path $run1 'firewall-before.wfw')) 'firewall exported first'
T-Has $r.Text 'ROLLBACK at' 'says when it rolls back'
T-Has $r.Text 'keep-firewall.ps1' 'says how to keep it'
T-Has ([IO.File]::ReadAllText((Join-Path $run1 'disabled.csv'))) '"Allow All","","*","allows every port, protocol and address","turned off"' 'disabled.csv records what was turned off'
$r = Run @('-Out', $out, '-Apply', '-Protected', $prot)
T-Eq $r.Code 2 'a second change while one waits for confirmation is refused'
T-Has $r.Text 'still waiting to be kept or rolled back' 'and says why'

T-Start 'the rollback fires'
$o = RunFile (Join-Path $run1 'rollback.ps1')
T-Eq (Snap) $start 'the firewall is exactly as before (profiles, every rule, logging)'
T-True (-not (Test-Path -LiteralPath (Join-Path $fake 'task.txt'))) 'the task is removed'
T-True (Test-Path -LiteralPath (Join-Path $run1 'ROLLED_BACK')) 'marked rolled back'
$o = RunFile (Join-Path $run1 'keep-firewall.ps1')
T-Has $o 'Too late' 'keeping after a rollback says it is too late'

T-Start 'kept from a new connection'
Plant
$r = Run @('-Out', $out, '-Apply', '-Protected', $prot)
$run2 = $r.Dir
$o = RunFile (Join-Path $run2 'keep-firewall.ps1')
T-Has $o 'Kept' 'keep says so'
T-True (-not (Test-Path -LiteralPath (Join-Path $fake 'task.txt'))) 'the rollback task is gone'
$afterKeep = Snap
$o = RunFile (Join-Path $run2 'rollback.ps1')
T-Eq (Snap) $afterKeep 'a rollback after keep does nothing'

T-Start 'a second run after keeping: no duplicate rules'
$before = @(Rules | Where-Object { $_.group -eq 'CCDC' }).Count
$r = Run @('-Out', $out, '-Apply', '-Protected', $prot)
T-Eq $r.Code 0 'exits 0'
T-Eq (@(Rules | Where-Object { $_.group -eq 'CCDC' }).Count) $before 'the same rules are not added again'
$o = RunFile (Join-Path $r.Dir 'keep-firewall.ps1')
$r = Run @('-Out', $out, '-Apply', '-Protected', $prot, '-AdminFrom', '10.0.0.9')
T-Eq (Rule 'CCDC allow admin and scoring hosts')[0].raddr '10.0.0.5,10.0.0.9' 'a rule with new addresses is replaced, not duplicated'
T-Eq (@(Rule 'CCDC allow admin and scoring hosts').Count) 1 'still one admin rule'
$o = RunFile (Join-Path $r.Dir 'keep-firewall.ps1')

T-Start 'a leftover task from a kept run does not block the next run'
# keep-firewall.ps1 from a window that could not delete the task: KEPT is
# written, the task stays.
[IO.File]::WriteAllText((Join-Path $fake 'task.txt'), 'leftover')
$r = Run @('-Out', $out, '-Apply', '-Protected', $prot)
T-Eq $r.Code 0 'the run goes ahead'
T-Has $r.Text 'removing a leftover rollback task' 'and says it removed the leftover task'
T-True (Test-Path -LiteralPath (Join-Path $fake 'task.txt')) 'a new rollback task is set for this run'
$o = RunFile (Join-Path $r.Dir 'keep-firewall.ps1')
[IO.File]::WriteAllText((Join-Path $fake 'task.txt'), 'leftover')
$o = RunFile (Join-Path $r.Dir 'rollback.ps1')
T-True (-not (Test-Path -LiteralPath (Join-Path $fake 'task.txt'))) 'a rollback that finds the run kept removes its task'

T-Start '-Undo and -Remove'
$r = Run @('-Out', $out, '-Remove', '-Apply', '-Protected', $prot)
T-Eq $r.Code 0 '-Remove exits 0'
T-Eq (@(Rules | Where-Object { $_.group -eq 'CCDC' }).Count) 0 'our rules are removed'
T-Eq (Enabled 'Allow All') 'False' '-Remove leaves the rest as it is'
Plant; $start = Snap
$r = Run @('-Out', $out, '-Apply', '-Protected', $prot, '-NoTimer', '-NoLog', '-NoPing')
T-True (-not (Test-Path -LiteralPath (Join-Path $fake 'task.txt'))) '-NoTimer: no task'
T-True (-not (Test-Path -LiteralPath (Join-Path $fake 'logging.txt'))) '-NoLog: logging not changed'
T-Eq (Enabled 'CCDC allow ping') '(none)' '-NoPing: no ping rule'
$r = Run @('-Out', $out, '-Undo', 'latest')
T-Has $r.Text 'nothing was put back' '-Undo without -Apply is a dry run'
$r = Run @('-Out', $out, '-Undo', 'latest', '-Apply', '-Protected', $prot)
T-Eq $r.Code 0 '-Undo exits 0'
T-Eq (Snap) $start 'the firewall is exactly as before'

T-Start '-Strict on a domain controller'
Plant; [IO.File]::WriteAllText((Join-Path $fake 'is-dc'), '')
$r = Run @('-Out', $out, '-Apply', '-Protected', $prot, '-Strict', '-NoTimer')
T-Eq (Enabled 'SQL Server') 'False' '-Strict turns off rules that are not ours'
T-Eq (Enabled 'Remote Desktop - User Mode (TCP-In)') 'False' 'including Windows rules (RDP is open through our rule)'
T-Eq (Enabled 'CCDC allow 3389/tcp') 'True' '... which exists'
T-Eq (Enabled 'Active Directory Domain Services (LDAP-In)') 'True' 'Active Directory rules are kept on a DC'
T-Eq (Enabled 'CCDC allow 88/tcp') 'True' 'Kerberos opened on a DC'
T-Eq (Enabled 'CCDC allow 3268-3269/tcp') 'True' 'global catalog opened on a DC'
T-Eq (Rule 'CCDC allow RPC (DC)')[0].lports 'RPC' 'dynamic RPC opened on a DC'
T-Has $r.Text 'domain controller: Active Directory ports kept open' 'summary says it is a DC'

T-Start 'nothing changes when the export fails'
Plant; $start = Snap
$env:CCDC_WN25_FAIL = 'export'
$r = Run @('-Out', $out, '-Apply', '-Protected', $prot)
Remove-Item Env:\CCDC_WN25_FAIL
T-Eq $r.Code 4 'exits 4'
T-Has $r.Text 'could not export the firewall first, so nothing was changed' 'and says why'
T-Eq (Snap) $start 'nothing changed'

T-Start 'no admin addresses: warned'
Plant
$p2 = Join-Path $tmp 'p2.csv'; [IO.File]::WriteAllLines($p2, [string[]]@('type,value,note', 'port,25/tcp,mail'))
$r = Run @('-Out', $out, '-Protected', $p2)
T-Has $r.Text 'WARNING: no admin or scoring addresses' 'a plan without admin addresses is warned about'

Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
exit 0
