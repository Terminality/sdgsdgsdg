# =============================================================================
# Tests for WN-16 Windows web shell hunter.
#   pwsh -NoProfile -File tests/wn16.Tests.ps1
#
# Stand-in: a temp folder with an applicationHost.config (two sites), planted
# shells (Process.Start with Request, a one-liner, classic ASP Execute, PHP
# in uploads, PHP inside a .jpg, a web.config that runs .jpg files, a known
# shell name, a program in the site) beside normal pages that must stay
# quiet.  Checks: the folders found, each finding and its level, a dry run
# changes nothing, -Apply quarantines HIGH only, revert.ps1 puts them back,
# the page check puts files back, the protected list, -Exclude, -WebRoot, the
# questions.
# =============================================================================
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
$wn16 = Join-Path (Join-Path (Join-Path $root 'roles') 'windows-ad') 'WN-16-webshell-hunter.ps1'
$psExe = (Get-Process -Id $PID).Path
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('cctest_wn16_' + $PID)
$out = Join-Path $tmp 'out'
$fake = Join-Path $tmp 'state'
$env:BT_SKIP_VERIFY = '1'; $env:BT_WN16_FAKE = $fake
$script:pass = 0; $script:fail = 0
function T-Start($t) { Write-Host "  -- $t" }
function T-Eq($got, $want, $label) { if ("$got" -ceq "$want") { $script:pass++ } else { $script:fail++; Write-Host "     FAIL: $label"; Write-Host "           got [$got], wanted [$want]" } }
function T-True($cond, $label) { if ($cond) { $script:pass++ } else { $script:fail++; Write-Host "     FAIL: $label" } }
function T-Has($text, $needle, $label) { T-True ("$text".Contains($needle)) "$label (missing [$needle])" }
function T-HasNot($text, $needle, $label) { T-True (-not "$text".Contains($needle)) "$label (found [$needle])" }
function Run([string[]]$a) {
    $all = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $wn16) + @($a)
    $text = (& $psExe @all 2>&1 | Out-String)
    $dir = ''; if ($text -match 'All results: (\S+)') { $dir = $matches[1].Trim() }
    return @{ Code = $LASTEXITCODE; Text = $text; Dir = $dir }
}
$S = [IO.Path]::DirectorySeparatorChar
$www = Join-Path (Join-Path $fake 'inetpub') 'wwwroot'
$ord = Join-Path (Join-Path $fake 'sites') 'order'
function F([string]$rel, [string]$text, [switch]$Old) {
    $p = Join-Path $fake ($rel -replace '\\', $S)
    $d = Split-Path -Parent $p; if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    [IO.File]::WriteAllText($p, $text)
    if ($Old) { (Get-Item -LiteralPath $p).LastWriteTime = [DateTime]::Now.AddDays(-30) }
    return $p
}
$ev = 'ev' + 'al'; $rq = 'Req' + 'uest'
function Plant {
    if (Test-Path -LiteralPath $fake) { Remove-Item -LiteralPath $fake -Recurse -Force }
    New-Item -ItemType Directory -Path $fake -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $fake 'applicationHost.config'), @'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.applicationHost>
    <sites>
      <site name="Default Web Site" id="1">
        <application path="/"><virtualDirectory path="/" physicalPath="%SystemDrive%\inetpub\wwwroot" /></application>
        <application path="/order"><virtualDirectory path="/" physicalPath="%SystemDrive%\sites\order" /></application>
      </site>
      <site name="Gone" id="2">
        <application path="/"><virtualDirectory path="/" physicalPath="%SystemDrive%\nothere" /></application>
      </site>
    </sites>
  </system.applicationHost>
</configuration>
'@)
    $script:normal = F 'inetpub\wwwroot\default.aspx' '<%@ Page Language="C#" %><html><body>Food ordering</body></html>' -Old
    $script:cmd = F 'inetpub\wwwroot\status.aspx' ('<%@ Page Language="C#" %><% System.Diagnostics.Process.Start("cmd.exe", "/c " + ' + $rq + '["c"]); %>') -Old
    $script:chop = F 'inetpub\wwwroot\x.aspx' ('<%@ Page Language="Jscript"%><%' + $ev + '(' + $rq + '.Item["z"],"unsafe");%>') -Old
    $script:tool = F 'inetpub\wwwroot\tool.exe' 'MZ' -Old
    $script:menu = F 'sites\order\menu.asp' ('<% Execute ' + $rq + '("c") %>') -Old
    $script:med = F 'sites\order\admin\tools.aspx' '<% var p = new ProcessStartInfo("ipconfig"); %>' -Old
    $script:upl = F 'sites\order\uploads\avatar.php' '<?php echo 1; ?>' -Old
    $script:jpg = F 'sites\order\images\logo.jpg' 'GIF89a<?php echo 2; ?>' -Old
    $script:wcfg = F 'sites\order\images\web.config' '<add name="x" path="*.jpg" verb="*" modules="IsapiModule" scriptProcessor="c:\php\php-cgi.exe" />' -Old
    $script:okcfg = F 'sites\order\web.config' '<configuration><system.webServer></system.webServer></configuration>' -Old
    $script:named = F 'sites\order\aspxspy.aspx' '<html>hello</html>' -Old
    $script:fresh = F 'sites\order\new.aspx' '<html>new menu</html>'
    $script:dll = F 'sites\order\bin\app.dll' 'MZ' -Old
}
$prot = Join-Path $tmp 'protected.txt'
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
[IO.File]::WriteAllLines($prot, [string[]]@('service W3SVC scored web'))

T-Start 'options'
Plant
$r = Run @('-Out', $out, '-Timer', '5'); T-Eq $r.Code 2 '-Timer under 30 exits 2'
$r = Run @('-Out', $out, '-Hours', '0'); T-Eq $r.Code 2 '-Hours 0 exits 2'
$r = Run @('-Out', $out, '-Url', 'ftp://x'); T-Eq $r.Code 2 'a -Url that is not http exits 2'

T-Start 'find (dry run, -Batch)'
Plant
$r = Run @('-Out', $out, '-Protected', $prot, '-Batch')
T-Eq $r.Code 0 'exit 0'
T-Has $r.Text 'WN-16 Windows web shell hunter | host' 'the title line'
T-Has $r.Text '[?] Another folder to scan (a site that is not in IIS)? none (default)' 'the folder question'
T-Has $r.Text ($www + '   (IIS site Default Web Site /)') 'the IIS site folder is found'
T-Has $r.Text ($ord + '   (IIS site Default Web Site /order)') 'the application folder is found'
T-HasNot $r.Text 'nothere' 'a folder that is not there is skipped'
T-Has $r.Text ('HIGH ' + $cmd + ' - runs request data as a command') 'Process.Start with Request is HIGH'
T-Has $r.Text ('HIGH ' + $chop + ' - runs request data as code') 'a one-liner is HIGH'
T-Has $r.Text 'one-line web shell (China Chopper style)' 'and named'
T-Has $r.Text ('HIGH ' + $menu + ' - runs request data as code') 'classic ASP Execute Request is HIGH'
T-Has $r.Text ('HIGH ' + $upl + ' - code in an upload or image folder') 'PHP in uploads is HIGH'
T-Has $r.Text ('HIGH ' + $jpg + ' - code hidden inside an image or text file') 'PHP inside a .jpg is HIGH'
T-Has $r.Text ('HIGH ' + $wcfg + ' - makes image or text files run as code') 'a web.config that runs .jpg is HIGH'
T-Has $r.Text ('HIGH ' + $named + ' - known web shell file name') 'a known shell name is HIGH'
T-Has $r.Text ('MED  ' + $med + ' - runs programs') 'ProcessStartInfo alone is MED'
T-Has $r.Text ('MED  ' + $tool + ' - a program or script in the site folder') 'a program in the site is MED'
T-HasNot $r.Text ($normal + ' -') 'a normal page stays quiet'
T-HasNot $r.Text ($okcfg + ' -') 'a normal web.config stays quiet'
T-HasNot $r.Text 'app.dll' 'bin\*.dll is not flagged'
T-HasNot $r.Text ($fresh + ' -') 'LOW is not on screen without -ShowLow'
T-Has $r.Text '1 LOW file(s) (changed lately) are in findings.txt' 'but counted'
T-Has $r.Text 'line: <% Execute' 'the matching line is shown'
T-Has $r.Text ($cmd + ' -> quarantine (default)') 'HIGH defaults to quarantine'
T-Has $r.Text ($med + ' -> keep (default)') 'MED defaults to keep'
T-Has $r.Text 'Dry run: nothing was changed' 'a dry run'
T-True ((Test-Path -LiteralPath $cmd) -and (Test-Path -LiteralPath $jpg)) 'and nothing moved'
T-True ($r.Dir -match 'webshells-\d+$') 'a numbered webshells-N folder'
$ft = [IO.File]::ReadAllText((Join-Path $r.Dir 'findings.txt'))
T-Has $ft 'changed in the last 24 hours' 'findings.txt has the LOW file'
T-True (Test-Path -LiteralPath (Join-Path $r.Dir 'folders.txt')) 'folders.txt written'
T-True (@(Get-ChildItem -LiteralPath $r.Dir -Recurse -Filter '*.csv').Count -eq 0) 'no CSV in the results'
$r = Run @('-Out', $out, '-Protected', $prot, '-Batch', '-ShowLow')
T-Has $r.Text ('LOW  ' + $fresh + ' - changed in the last 24 hours') '-ShowLow lists it'

T-Start 'apply the defaults, then revert'
Plant
$env:BT_TEST_SCHTASKS = Join-Path $tmp 'schtasks.log'
$r = Run @('-Out', $out, '-Protected', $prot, '-Batch', '-Apply')
T-Eq $r.Code 0 'exit 0'
T-True (-not (Test-Path -LiteralPath $cmd)) 'a HIGH file is moved out'
T-True (-not (Test-Path -LiteralPath $jpg)) 'and the .jpg with code'
T-True (Test-Path -LiteralPath $med) 'MED is kept by default'
T-True (Test-Path -LiteralPath $normal) 'a normal page is not touched'
T-True (@(Get-ChildItem -LiteralPath (Join-Path $out 'quarantine') -Recurse -Filter 'status.aspx').Count -eq 1) 'it is in the quarantine folder'
T-Has $r.Text '[ok] the site still loads' 'the page check ran'
T-Has $r.Text 'Quarantined: 7   Put back: 0   Failed: 0' 'the summary counts'
& $psExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $r.Dir 'revert.ps1') -Force 2>&1 | Out-Null
T-True ((Test-Path -LiteralPath $cmd) -and (Test-Path -LiteralPath $jpg)) 'revert.ps1 puts them back'
Remove-Item Env:\BT_TEST_SCHTASKS

T-Start 'the site stops loading: the files go back'
Plant
[IO.File]::WriteAllLines((Join-Path $fake 'site-needs.txt'), [string[]]@($named))
$env:BT_TEST_SCHTASKS = Join-Path $tmp 'schtasks2.log'
$r = Run @('-Out', $out, '-Protected', $prot, '-Batch', '-Apply')
Remove-Item Env:\BT_TEST_SCHTASKS
T-Has $r.Text 'the site stopped loading: putting the files back' 'noticed'
T-Has $r.Text '[ok] the site loads again' 'and back'
T-True ((Test-Path -LiteralPath $named) -and (Test-Path -LiteralPath $cmd)) 'every file is back'
T-Has $r.Text 'Put back: 7' 'counted'

T-Start 'the protected list, -Exclude, -WebRoot'
Plant
$p2 = Join-Path $tmp 'prot2.txt'
[IO.File]::WriteAllLines($p2, [string[]]@('service W3SVC scored web', ('path ' + $upl + ' the menu upload')))
$env:BT_TEST_SCHTASKS = Join-Path $tmp 'schtasks3.log'
$r = Run @('-Out', $out, '-Protected', $p2, '-Batch', '-Apply', '-Exclude', 'menu.asp')
Remove-Item Env:\BT_TEST_SCHTASKS
T-True (Test-Path -LiteralPath $upl) 'a protected path is never moved'
T-HasNot $r.Text ('HIGH ' + $menu) '-Exclude leaves a path out'
T-True (Test-Path -LiteralPath $menu) 'and it stays'
$extra = Join-Path $tmp 'extra'; New-Item -ItemType Directory -Path $extra -Force | Out-Null
$shell2 = Join-Path $extra 'up.aspx'; [IO.File]::WriteAllText($shell2, ('<% ' + $ev + '(' + $rq + '["a"]) %>'))
$r = Run @('-Out', $out, '-Protected', $prot, '-Batch', '-WebRoot', $extra)
T-Has $r.Text ($extra + '   (-WebRoot)') '-WebRoot adds a folder'
T-HasNot $r.Text 'Another folder to scan' '-WebRoot answers the question'
T-Has $r.Text ('HIGH ' + $shell2) 'and it is scanned'

T-Start 'the questions'
Plant
# folder: the extra one; HIGH files in path order: first k, then a (the rest default); apply y; keep y
$env:BT_TEST_SCHTASKS = Join-Path $tmp 'schtasks4.log'
$env:BT_TEST_ANSWERS = ($extra + ';k;a;y;y')
$r = Run @('-Out', $out, '-Protected', $prot)
Remove-Item Env:\BT_TEST_ANSWERS; Remove-Item Env:\BT_TEST_SCHTASKS
T-Has $r.Text '[q] quarantine it' 'each file lists its answers'
T-Has $r.Text ($extra + '   (typed)') 'the typed folder is scanned'
T-True (Test-Path -LiteralPath $shell2) 'k: kept (the first HIGH, in the typed folder)'
T-True (-not (Test-Path -LiteralPath $cmd)) 'a: the rest take their default'
T-Has $r.Text 'Changes kept' 'keep: y'

Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
exit 0
