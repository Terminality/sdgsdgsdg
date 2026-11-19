# =============================================================================
# Tests for lib/lib.ps1 (LB-02).
#   Run through tests/run-tests.sh, or directly:
#       pwsh -NoProfile -File tests/lib.Tests.ps1
#       powershell -NoProfile -ExecutionPolicy Bypass -File tests\lib.Tests.ps1
#
# No Pester dependency, and written in PowerShell 2.0 syntax so the same file
# can be run on an old Windows test VM.  Each scenario is a throw-away script
# run in a child PowerShell, because library functions end the process
# (Stop-Cc, Complete-Cc) and the test must survive that and read the exit code.
# =============================================================================
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
$lib = Join-Path (Join-Path $root 'lib') 'lib.ps1'
$psExe = (Get-Process -Id $PID).Path
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('cctest_ps_' + $PID)
$sdir = Join-Path $tmp 's'      # throw-away scripts live here, apart from the output folder
$out = Join-Path $tmp 'out'
New-Item -ItemType Directory -Path $sdir -Force | Out-Null
$env:BT_SKIP_VERIFY = '1'
$script:pass = 0; $script:fail = 0

function T-Start($t) { Write-Host "  -- $t" }
function T-Eq($got, $want, $label) {
    if ("$got" -ceq "$want") { $script:pass++ } else { $script:fail++; Write-Host "     FAIL: $label"; Write-Host "           got [$got], wanted [$want]" }
}
function T-True($cond, $label) { if ($cond) { $script:pass++ } else { $script:fail++; Write-Host "     FAIL: $label" } }
function T-Has($text, $needle, $label) { T-True ("$text".Contains($needle)) "$label (missing [$needle])" }
function T-HasNot($text, $needle, $label) { T-True (-not "$text".Contains($needle)) "$label (found [$needle])" }

# Mk name body -> write a script with the standard parameters that loads the lib.
$head = @'
param([switch]$Apply,[string]$Out,[string]$Protected,[switch]$NoProtected,[switch]$ForceScored,[switch]$Quiet,[switch]$DebugLog,[string]$Mine)
. 'LIBPATH'
'@.Replace('LIBPATH', $lib.Replace("'", "''"))
function Mk($name, $body) {
    $p = Join-Path $sdir ($name + '.ps1')
    [IO.File]::WriteAllText($p, $head + "`r`n" + $body + "`r`n")
    return $p
}
# Run script args... -> @{ Code; Text } from a child PowerShell.
function Run($script, [string[]]$a) {
    $all = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $script) + @($a)
    $text = (& $psExe @all 2>&1 | Out-String)
    return @{ Code = $LASTEXITCODE; Text = $text }
}

T-Start 'init and common parameters'
$s = Mk 'init' @'
Initialize-Cc -Id 'T-01' -Name 'init test' -Kind readonly -Bound $PSBoundParameters
Write-Host ("apply={0} mine={1} out={2}" -f $Cc.Apply, $Mine, $Cc.Out)
Complete-Cc
'@
$r = Run $s @('-Out', $out, '-Mine', 'hello')
T-Eq $r.Code 0 'readonly dry run exits 0'
T-Has $r.Text 'apply=False mine=hello' 'dry run is the default; own parameter still works'
T-Has $r.Text 'READ-ONLY' "a read-only script's banner says READ-ONLY"
$r = Run $s @('-Out', $out, '-Apply'); T-Has $r.Text 'apply=True' '-Apply is picked up from the bound parameters'
T-True (@(Get-ChildItem -LiteralPath $out -Filter 'T-01_*.log').Count -ge 1) 'a log file was created'

T-Start 'output folder may not be inside the kit'
$r = Run $s @('-Out', (Join-Path $sdir 'out')); T-Eq $r.Code 2 "refuses -Out inside the script's own folder"

T-Start "apply without a protected list is refused for 'changes' scripts"
$mark = Join-Path $tmp 'marker.txt'
$s = Mk 'chg' @'
Initialize-Cc -Id 'T-02' -Name 'change test' -Kind changes -Bound $PSBoundParameters
Invoke-CcChange -Description 'make marker' -Action { Set-Content -LiteralPath $Mine -Value x } -Undo 'Remove-Item x' | Out-Null
Complete-Cc
'@
$r = Run $s @('-Out', $out, '-Apply', '-Mine', $mark); T-Eq $r.Code 3 'exit 3 with no protected list'
T-True (-not (Test-Path -LiteralPath $mark)) 'nothing was changed'
$r = Run $s @('-Out', $out, '-Mine', $mark); T-Eq $r.Code 0 'dry run needs no protected list'
T-True (-not (Test-Path -LiteralPath $mark)) 'dry run changed nothing'
T-Has $r.Text 'would-change=1' 'dry run counted the change'
$r = Run $s @('-Out', $out, '-Apply', '-NoProtected', '-Mine', $mark); T-Eq $r.Code 0 '-NoProtected allows apply'
T-True (Test-Path -LiteralPath $mark) 'apply made the change'

T-Start 'Invoke-CcChange counts failures (throw, cmdlet error, program exit code) and exits 5'
$s = Mk 'fail' @'
Initialize-Cc -Id 'T-03' -Name 'fail test' -Kind changes -Bound $PSBoundParameters
$a = Invoke-CcChange -Description 'throws' -Action { throw 'boom' }
$b = Invoke-CcChange -Description 'cmdlet error' -Action { Get-Item -LiteralPath 'Z:\no\such\thing\anywhere' }
$c = Invoke-CcChange -Description 'works' -Action { 1 + 1 }
Write-Host ("results={0},{1},{2}" -f $a, $b, $c)
Complete-Cc
'@
$r = Run $s @('-Out', $out, '-Apply', '-NoProtected')
T-Eq $r.Code 5 'exit 5 when a change failed'
T-Has $r.Text 'results=False,False,True' 'each call reports its own result'
T-Has $r.Text 'changed=1' 'one success counted'; T-Has $r.Text 'failed=2' 'two failures counted'

T-Start 'programs: judged by exit code, stderr text alone is not a failure'
if ([Environment]::OSVersion.Platform -eq 'Win32NT') { $exe = 'cmd.exe'; $okArgs = "'/c','echo warn 1>&2 & exit 0'"; $badArgs = "'/c','echo out & exit 7'" }
else { $exe = 'sh'; $okArgs = "'-c','echo warn >&2; exit 0'"; $badArgs = "'-c','echo out; exit 7'" }
$s = Mk 'prog' (@'
Initialize-Cc -Id 'T-09' -Name 'program test' -Kind changes -Bound $PSBoundParameters
$a = Invoke-CcChange -Description 'stderr but exit 0' -Action { Invoke-CcProgram -FilePath 'EXE' -Arguments @(OKARGS) }
$b = Invoke-CcChange -Description 'exit 7' -Action { Invoke-CcProgram -FilePath 'EXE' -Arguments @(BADARGS) }
Write-Host ("results={0},{1}" -f $a, $b)
Complete-Cc
'@.Replace('EXE', $exe).Replace('OKARGS', $okArgs).Replace('BADARGS', $badArgs))
$r = Run $s @('-Out', $out, '-Apply', '-NoProtected')
T-Has $r.Text 'results=True,False' 'stderr output with exit 0 succeeds; exit 7 fails'
T-Eq $r.Code 5 'the failed program makes the script exit 5'
$logs = (Get-ChildItem -LiteralPath $out -Filter 'T-09_*.log' | ForEach-Object { [IO.File]::ReadAllText($_.FullName) }) -join "`n"
T-Has $logs 'warn' "the program's stderr text is kept in the log"
T-Has $logs 'program exit code 7' 'the log names the exit code'

T-Start '-Secret keeps output out of the log'
$s = Mk 'secret' @'
Initialize-Cc -Id 'T-04' -Name 'secret test' -Kind changes -Bound $PSBoundParameters
Invoke-CcChange -Description 'set a password' -Secret -Action { 'S3cretValue' } | Out-Null
Invoke-CcChange -Description 'visible step' -Action { 'VisibleOutput' } | Out-Null
Complete-Cc
'@
$r = Run $s @('-Out', $out, '-Apply', '-NoProtected')
T-HasNot $r.Text 'S3cretValue' 'secret is not printed'
$logs = (Get-ChildItem -LiteralPath $out -Filter 'T-04_*.log' | ForEach-Object { [IO.File]::ReadAllText($_.FullName) }) -join "`n"
T-HasNot $logs 'S3cretValue' 'secret is not in the log'
T-Has $logs 'VisibleOutput' 'normal output is in the log'

T-Start 'protected list'
$prot = Join-Path $tmp 'prot.csv'
[IO.File]::WriteAllText($prot, "type,value,note`r`n# comment`r`nport,80/tcp,scored web`r`nport,53,dns`r`nservice,W3SVC,scored`r`n`"account`",`"svc-web`",`"scoring login`"`r`npath,C:\inetpub,site`r`n")
$s = Mk 'prot' @'
Initialize-Cc -Id 'T-05' -Name 'guard test' -Kind changes -Bound $PSBoundParameters
function Chk($t, $v) { if (Test-CcProtected -Type $t -Value $v) { 'yes' } else { 'no' } }
Write-Host ("a={0} b={1} c={2} d={3} e={4} f={5} g={6} h={7}" -f (Chk port '80/tcp'), (Chk port '80'), (Chk port '80/udp'), (Chk port '53/udp'), (Chk port '8080'), (Chk service 'w3svc'), (Chk account 'SVC-WEB'), (Chk account 'administrator'))
if (Test-CcAllowed -Type port -Value 80) { Write-Host 'port-allowed' }
if (Test-CcAllowed -Type port -Value 8080) { Write-Host '8080-allowed' }
if (Test-CcAllowed -Type account -Value 'svc-web') { Write-Host 'account-allowed' }
Complete-Cc
'@
$r = Run $s @('-Out', $out, '-Protected', $prot, '-Apply')
T-Has $r.Text 'a=yes b=yes c=no d=yes e=no f=yes g=yes h=no' 'matching rules (case, quotes, comments, port forms)'
T-HasNot $r.Text 'port-allowed' 'protected port refused'; T-Has $r.Text '8080-allowed' 'unlisted port allowed'
T-HasNot $r.Text 'account-allowed' 'protected account refused'; T-Has $r.Text 'refused=2' 'refusals counted'
$r = Run $s @('-Out', $out, '-Protected', $prot, '-Apply', '-ForceScored')
T-Has $r.Text 'account-allowed' '-ForceScored overrides for accounts'; T-HasNot $r.Text 'port-allowed' '-ForceScored does not override ports'

T-Start 'backup, undo log and quarantine'
$target = Join-Path $tmp "it's a file.conf"; $bad = Join-Path $tmp 'bad file.ps1'
$s = Mk 'bk' @'
Initialize-Cc -Id 'T-06' -Name 'backup test' -Kind changes -Bound $PSBoundParameters
$t = $Mine.Split('|')[0]; $b = $Mine.Split('|')[1]
$bk = Backup-CcFile -Path $t
if ($null -eq $bk) { Stop-Cc -Code 1 -Message 'backup failed' }
if ($Cc.Apply) { Set-Content -LiteralPath $t -Value 'changed' }
Move-CcQuarantine -Path $b | Out-Null
Write-Host ("undo=" + $Cc.Undo)
Complete-Cc
'@
Set-Content -LiteralPath $target -Value 'original'; Set-Content -LiteralPath $bad -Value 'evil'
$r = Run $s @('-Out', $out, '-Mine', "$target|$bad")
T-Eq ((Get-Content -LiteralPath $target) -join '') 'original' 'dry run leaves the file alone'
T-True (Test-Path -LiteralPath $bad) 'dry run does not quarantine'
$r = Run $s @('-Out', $out, '-Apply', '-NoProtected', '-Mine', "$target|$bad")
T-Eq ((Get-Content -LiteralPath $target) -join '') 'changed' 'apply changed the file'
T-True (-not (Test-Path -LiteralPath $bad)) 'apply quarantined the bad file'
$undo = Join-Path $out ('undo-' + ((([Environment]::MachineName) -split '\.')[0] -replace '[^A-Za-z0-9_-]', '_') + '.log')
T-True (Test-Path -LiteralPath $undo) 'undo log exists'
# Roll back by running the undo commands newest first, exactly as an operator would.
$cmds = @(Get-Content -LiteralPath $undo | Where-Object { $_ -match "`tT-06`t" } | ForEach-Object { ($_ -split "`t")[3] })
[array]::Reverse($cmds)
foreach ($cmd in $cmds) { Invoke-Expression $cmd }
T-Eq ((Get-Content -LiteralPath $target) -join '') 'original' 'undo restored the file (name has a quote and spaces)'
T-True (Test-Path -LiteralPath $bad) 'undo put the quarantined file back'

T-Start 'passwords, hashing, csv, findings (in-process)'
. $lib
$pw = @(); for ($i = 0; $i -lt 20; $i++) { $pw += (New-CcPassword) }
$pw += (New-CcPassword -Length 24)
T-Eq (@($pw | Where-Object { $_.Length -ne 16 }).Count) 1 'length is 16 by default'
T-Eq $pw[20].Length 24 'custom length works'
T-Eq (@($pw | Where-Object { $_ -cmatch '[^A-HJ-NP-Za-km-z2-9_-]' }).Count) 0 'only allowed characters (no look-alikes)'
T-Eq (@($pw | Where-Object { $_ -match '^[-_]' }).Count) 0 'never starts with - or _'
T-Eq (@($pw | Sort-Object -Unique).Count) 21 'all different'
T-Eq (@($pw | Where-Object { $_ -cmatch '[A-Z]' -and $_ -cmatch '[a-z]' -and $_ -match '[0-9]' }).Count) 21 'each has upper, lower and digit'
$abc = Join-Path $tmp 'abc.txt'; [IO.File]::WriteAllText($abc, 'abc')
T-Eq (Get-CcSha256 -Path $abc) 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' 'sha256 of abc is correct'
T-Eq (ConvertTo-CcCsvLine -Values @('plain', 'has "quotes", and comma', '')) '"plain","has ""quotes"", and comma",""' 'quotes doubled, empty field kept'
T-Eq (ConvertTo-CcCsvLine -Values @($null, "two`r`nlines", 5)) '"","two lines","5"' 'null and line break handled, number converted'
T-Eq (ConvertTo-CcQuoted "a'b c") "'a''b c'" 'PowerShell quoting'
$s = Mk 'find' @'
Initialize-Cc -Id 'T-07' -Name 'findings test' -Kind readonly -Bound $PSBoundParameters
Add-CcFinding -Weakness 'telnet running' -FixId FIX-TELNET -Class safe -Detail 'port 23 open'
Add-CcFinding -Weakness 'smbv1 on' -FixId FIX-SMB1 -Class service -Detail 'scored share uses it' -ProtectedDep 'port 445'
Write-Host ("find=" + $Cc.Findings)
Complete-Cc
'@
$r = Run $s @('-Out', $out)
$ff = ($r.Text -split "`r?`n" | Where-Object { $_ -like 'find=*' }) -replace '^find=', ''
$fl = @(Get-Content -LiteralPath $ff)
T-Eq $fl[0] 'host,script,weakness,fix_id,class,protected_dep,detail,time' 'findings header'
T-Has $fl[2] '"FIX-SMB1","service","port 445"' 'finding row has fix id, class and dependency'
T-Has $r.Text 'findings=2' 'findings counted'

T-Start 'run folder, raw capture and flags'
$s = Mk 'flags' @'
Initialize-Cc -Id 'T-10' -Name 'flags test' -Kind readonly -Bound $PSBoundParameters
Use-CcRunDir
$f = New-CcCsv -Name things -Header @('a','b')
$raw = Save-CcOutput -Name ver -Command { $PSVersionTable.PSVersion.ToString() }
$bad = Save-CcOutput -Name broken -Command { Get-Item -LiteralPath 'Z:\no\such\path\here' }
Add-CcFlag -Severity LOW -Section users -Item bob -Detail 'low one'
Add-CcFlag -Severity HIGH -Section ports -Item '4444/tcp' -Detail 'nc listening, "quoted", with comma'
Add-CcFlag -Severity MED -Section ssh -Item root -Detail 'medium one'
Add-CcFlag -Severity HIGH -Section files -Item 'C:\tmp\x' -Detail 'second high'
Write-Host ('run=' + $Cc.RunDir); Write-Host ('csv=' + $f); Write-Host ('raw=' + $raw); Write-Host ('bad=' + $bad)
Show-CcFlagReport -Max 2
[IO.File]::WriteAllText((Join-Path $Cc.RunDir 'report30.txt'), ((Get-CcFlagReport -Max 30) -join "`n"))
$first = $Cc.RunDir; Use-CcRunDir; Write-Host ('second=' + $Cc.RunDir); $Cc.RunDir = $first; $Cc.CsvDir = $first
Complete-Cc
'@
$r = Run $s @('-Out', $out)
$lines = $r.Text -split "`r?`n"
$runDir = ($lines | Where-Object { $_ -like 'run=*' }) -replace '^run=', ''
T-Eq (($lines | Where-Object { $_ -like 'second=*' }) -replace '^second=', '') ($runDir + '-2') 'a second run folder in the same second gets -2'
T-Eq (($lines | Where-Object { $_ -like 'csv=*' }) -replace '^csv=', '') (Join-Path $runDir 'things.csv') 'CSV goes into the run folder'
T-Has ([IO.File]::ReadAllText((Join-Path (Join-Path $runDir 'raw') 'ver.txt'))) $PSVersionTable.PSVersion.ToString() 'raw output saved'
T-Has ([IO.File]::ReadAllText((Join-Path (Join-Path $runDir 'raw') 'broken.txt'))) 'Cannot find' 'a failing block is recorded, not fatal'
T-Eq $r.Code 0 'script still exits 0 after a failing capture'
T-Eq (@(Get-Content -LiteralPath (Join-Path $runDir 'flags.csv')).Count) 5 'four flags plus header'
T-Has $r.Text 'Flags: 2 high, 1 medium, 1 low' 'report counts'
T-Has $r.Text '[ports] 4444/tcp: nc listening, "quoted", with comma' 'report keeps quotes and commas intact'
T-HasNot $r.Text 'medium one' 'Max 2 cuts the list'
T-Has $r.Text '1 more high/medium not shown' 'report says how many were cut'
$rep30 = [IO.File]::ReadAllText((Join-Path $runDir 'report30.txt'))
T-Has $rep30 'MED - look soon' 'with room, MED lines are shown'
T-HasNot $rep30 'low one' 'LOW lines are never printed'
T-HasNot $r.Text 'FLAG HIGH' 'flags are not printed while the script runs'

T-Start 'kit integrity check'
$env:BT_SKIP_VERIFY = $null
$dist = Join-Path $tmp 'dist'; New-Item -ItemType Directory -Path $dist -Force | Out-Null
$v = Join-Path $dist 'v.ps1'; Copy-Item -LiteralPath (Join-Path $sdir 'init.ps1') -Destination $v
[IO.File]::WriteAllText((Join-Path $dist 'MANIFEST.sha256'), ((Get-CcSha256 -Path $v) + '  v.ps1' + "`n"))
$r = Run $v @('-Out', $out); T-Eq $r.Code 0 'untouched script passes the manifest check'
Add-Content -LiteralPath $v -Value '# tampered'
$r = Run $v @('-Out', $out); T-Eq $r.Code 3 'edited script is refused with exit 3'
T-Has $r.Text 'KIT CHECK FAILED' 'message explains why'
$env:BT_SKIP_VERIFY = '1'
$r = Run $v @('-Out', $out); T-Eq $r.Code 0 'BT_SKIP_VERIFY=1 bypasses the check'

T-Start 'the PowerShell template runs as a dry run and writes its files'
$r = Run (Join-Path (Join-Path $root 'templates') 'script-template.ps1') @('-Out', $out, '-Example', 'hello')
T-Eq $r.Code 0 'template exits 0'
T-Has $r.Text 'READ-ONLY' 'the template starts as a read-only script'
$tcsv = @(Get-ChildItem -LiteralPath $out -Filter 'XX-00_*_example.csv')
T-True ($tcsv.Count -ge 1 -and ([IO.File]::ReadAllText($tcsv[0].FullName)).Contains('"example option","hello"')) 'template csv has the option value'

Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 } else { exit 0 }
