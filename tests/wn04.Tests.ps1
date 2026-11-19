# Tests for WN-04. These are intentionally read-only and run on domain and
# non-domain machines. A real Server 2016/2019 DC remains required before the
# script can be marked tested.
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
$scriptFile = Join-Path (Join-Path (Join-Path $root 'roles') 'windows-ad') 'WN-04-ad-enum.ps1'
$psExe = (Get-Process -Id $PID).Path
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('cctest_wn04_' + $PID)
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$env:CCDC_SKIP_VERIFY = '1'
$script:pass = 0; $script:fail = 0
function T([bool]$ok,[string]$label) { if ($ok) { $script:pass++ } else { $script:fail++; Write-Host "     FAIL: $label" } }
function Run([string[]]$a) { $t = (& $psExe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $scriptFile @a 2>&1 | Out-String); return @{Code=$LASTEXITCODE;Text=$t} }

Write-Host '  -- help and options'
$r = Run @('-Help'); T ($r.Code -eq 0) 'help exits 0'; T ($r.Text.Contains('Active Directory enum')) 'help text'
$r = Run @('-EventHours','0'); T ($r.Code -eq 2) 'bad EventHours refused'
$r = Run @('-Apply'); T ($r.Code -eq 2) '-Apply refused for read-only script'

Write-Host '  -- live read-only run'
$r = Run @('-Out',$tmp)
T ($r.Code -eq 0) 'live or no-domain run exits 0'
T ((Get-ChildItem -LiteralPath $tmp -Recurse -Filter summary.txt -ErrorAction SilentlyContinue).Count -ge 1) 'summary written'

Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ('  {0} passed, {1} failed' -f $script:pass,$script:fail)
if ($script:fail -gt 0) { exit 1 }
exit 0
