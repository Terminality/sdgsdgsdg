# Tests for WN-44 option safety and a one-shot read-only check.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
$scriptFile = Join-Path (Join-Path (Join-Path $root 'roles') 'windows-ad') 'WN-44-windows-alerts.ps1'
$psExe = (Get-Process -Id $PID).Path
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('cctest_wn44_' + $PID)
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$env:CCDC_SKIP_VERIFY = '1'
$script:pass = 0; $script:fail = 0
function T([bool]$ok,[string]$label) { if ($ok) { $script:pass++ } else { $script:fail++; Write-Host "     FAIL: $label" } }
function Run([string[]]$a) { $t = (& $psExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $scriptFile @a 2>&1 | Out-String); return @{Code=$LASTEXITCODE;Text=$t} }

Write-Host '  -- help and guard rails'
$r = Run @('-Help'); T ($r.Code -eq 0) 'help exits 0'; T ($r.Text.Contains('Windows alerts')) 'help text'
$r = Run @('-Loop','5'); T ($r.Code -eq 2) 'unsafe tight loop refused'
$r = Run @('-Apply'); T ($r.Code -eq 2) '-Apply refused for read-only script'

Write-Host '  -- required read-only collectors are present'
$source = [IO.File]::ReadAllText($scriptFile)
T ($source.Contains("Cmd-Lines 'net.exe'")) 'account collector'
T ($source.Contains('Get-WmiObject Win32_Service')) 'service collector'
T ($source.Contains("Cmd-Lines 'schtasks.exe'")) 'task collector'
T ($source.Contains("Cmd-Lines 'netstat.exe'")) 'listener collector'
T ($source.Contains('wevtutil.exe')) 'event collector'
T ($source.Contains('Compare-Snapshot')) 'baseline diff'

Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ('  {0} passed, {1} failed' -f $script:pass,$script:fail)
if ($script:fail -gt 0) { exit 1 }
exit 0
