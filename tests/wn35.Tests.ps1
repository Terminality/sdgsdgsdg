# =============================================================================
# Tests for WN-35 Windows backup.
#   pwsh -NoProfile -File tests/wn35.Tests.ps1
#
# Off Windows (where these run in CI) the Windows programs are stand-ins:
# small sh scripts named reg.exe, netsh.exe, secedit.exe, auditpol.exe,
# icacls.exe and dnscmd.exe that write the files the real ones would, and a
# fake Windows folder (SystemRoot) with tasks, hosts, IIS, DNS, DHCP and
# SYSVOL.  That proves every item's flow, RESTORE.txt, hashes, the size limit
# and -CopyTo.  On Windows only the option checks run; run the script itself
# on a test VM.  Nothing outside the temp folder is touched.
# =============================================================================
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
$wn35 = Join-Path (Join-Path (Join-Path $root 'roles') 'windows-ad') 'WN-35-backup.ps1'
$psExe = (Get-Process -Id $PID).Path
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('cctest_wn35_' + $PID)
$out = Join-Path $tmp 'out'
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$env:CCDC_SKIP_VERIFY = '1'
$script:pass = 0; $script:fail = 0
function T-Start($t) { Write-Host "  -- $t" }
function T-Eq($got, $want, $label) { if ("$got" -ceq "$want") { $script:pass++ } else { $script:fail++; Write-Host "     FAIL: $label"; Write-Host "           got [$got], wanted [$want]" } }
function T-True($cond, $label) { if ($cond) { $script:pass++ } else { $script:fail++; Write-Host "     FAIL: $label" } }
function T-Has($text, $needle, $label) { T-True ("$text".Contains($needle)) "$label (missing [$needle])" }
function T-HasNot($text, $needle, $label) { T-True (-not "$text".Contains($needle)) "$label (found [$needle])" }
function Run([string[]]$a) {
    $all = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $wn35) + @($a)
    $text = (& $psExe @all 2>&1 | Out-String)
    $dir = ''; if ($text -match 'All results: (\S+)') { $dir = $matches[1].Trim() }
    return @{ Code = $LASTEXITCODE; Text = $text; Dir = $dir }
}
function ReadF($p) { if (Test-Path -LiteralPath $p) { return [IO.File]::ReadAllText($p) }; return '' }
function Item($dir, $name) { foreach ($r in @(Import-Csv -LiteralPath (Join-Path $dir 'items.csv'))) { if ($r.item -eq $name) { return $r } }; return $null }

T-Start 'options'
$r = Run @('-List'); T-Eq $r.Code 0 '-List exits 0'; T-Has $r.Text 'secpolicy' '-List names the items'
$r = Run @('-Out', $out, '-Only', 'nosuch'); T-Eq $r.Code 2 'an unknown item exits 2'
$r = Run @('-Out', $out, '-MaxMB', '0'); T-Eq $r.Code 2 '-MaxMB 0 exits 2'

if ([Environment]::OSVersion.Platform -eq 'Win32NT') {
    Write-Host '  (on Windows: the stand-in tests are skipped; run WN-35 itself on a test VM)'
} else {
    # ---- stand-in programs ------------------------------------------------
    $bin = Join-Path $tmp 'bin'; New-Item -ItemType Directory -Path $bin -Force | Out-Null
    $log = Join-Path $tmp 'calls.log'
    # The test file is checked out with CRLF (.gitattributes), and a CR at the
    # end of a line breaks /bin/sh, so it is stripped from the stub body.
    function Stub($name, $body) { $p = Join-Path $bin $name; [IO.File]::WriteAllText($p, "#!/bin/sh`necho `"$name `$*`" >>'$log'`n" + ($body -replace "`r", '') + "`n"); & chmod +x $p }
    Stub 'reg.exe' @'
case "$2" in *WOW6432Node*) echo "ERROR: The system was unable to find the specified registry key or value."; exit 1 ;; esac
printf 'Windows Registry Editor Version 5.00\r\n[%s]\r\n' "$2" >"$3"
'@
    Stub 'netsh.exe' @'
case "$1 $2" in
  "advfirewall export") echo fake-wfw >"$3"; echo Ok. ;;
  "advfirewall show") echo "Domain Profile Settings:"; echo "State ON" ;;
  "dhcp server") echo "dhcp scopes" >"$4"; echo "Command completed successfully." ;;
  *) exit 1 ;;
esac
'@
    Stub 'secedit.exe' @'
if [ "$FAIL_SECEDIT" = 1 ]; then echo "Task is completed. Errors occurred: access denied"; exit 5; fi
printf '[Unicode]\r\nUnicode=yes\r\n[Privilege Rights]\r\nSeDebugPrivilege = *S-1-5-32-544\r\n' >"$3"
'@
    Stub 'auditpol.exe' @'
f=${2#/file:}; echo "Machine Name,Policy Target,Subcategory" >"$f"
'@
    Stub 'icacls.exe' 'echo "processed file: $1"'
    Stub 'dnscmd.exe' @'
case "$1" in
  /enumzones) printf 'Enumerated zone list:\n\n Zone name                 Type       Storage         Properties\n\n .                         Cache      AD-Domain\n _msdcs.corp.local         Primary    AD-Forest       Secure\n corp.local                Primary    AD-Domain       Secure Rev\n 0.0.10.in-addr.arpa       Primary    AD-Domain       Secure Rev\n TrustAnchors              Primary    AD-Forest\n\nCommand completed successfully.\n' ;;
  /zoneexport) [ "$2" = "0.0.10.in-addr.arpa" ] && { echo "DNS Server failed to export zone."; exit 9; }
               echo "; zone $2" >"$SystemRoot/System32/dns/$3"; echo "Command completed successfully." ;;
esac
'@
    $env:PATH = $bin + [IO.Path]::PathSeparator + $env:PATH

    # ---- a fake Windows folder: a DC with IIS, DNS and DHCP ----------------
    $sr = Join-Path $tmp 'Windows'; $sd = Join-Path $tmp 'C'
    foreach ($d in @('System32/Tasks/Microsoft/Windows/Defrag', 'System32/drivers/etc', 'System32/inetsrv/config', 'System32/dns', 'System32/dhcp', 'SYSVOL/domain/scripts')) { New-Item -ItemType Directory -Path (Join-Path $sr $d) -Force | Out-Null }
    foreach ($d in @('inetpub/wwwroot', 'inetpub/shop', 'bigapp', 'app')) { New-Item -ItemType Directory -Path (Join-Path $sd $d) -Force | Out-Null }
    [IO.File]::WriteAllText((Join-Path $sr 'System32/Tasks/Microsoft/Windows/Defrag/ScheduledDefrag'), '<Task/>')
    [IO.File]::WriteAllText((Join-Path $sr 'System32/Tasks/Updater'), '<Task><Exec>evil.exe</Exec></Task>')
    [IO.File]::WriteAllText((Join-Path $sr 'System32/drivers/etc/hosts'), "127.0.0.1 localhost`r`n")
    [IO.File]::WriteAllText((Join-Path $sr 'System32/inetsrv/config/applicationHost.config'), '<sites><site name="Shop"><application path="/"><virtualDirectory path="/" physicalPath="%SystemDrive%\inetpub\shop" /></application></site><site name="Default"><virtualDirectory path="/" physicalPath="%SystemDrive%\inetpub\wwwroot" /></site></sites>')
    [IO.File]::WriteAllText((Join-Path $sd 'inetpub/wwwroot/index.html'), 'hello')
    [IO.File]::WriteAllText((Join-Path $sd 'inetpub/shop/cart.aspx'), 'shop')
    [IO.File]::WriteAllText((Join-Path $sr 'SYSVOL/domain/scripts/logon.bat'), '@echo off')
    [IO.File]::WriteAllText((Join-Path $sd 'app/app.config'), 'connection=x')
    $big = New-Object byte[] (2MB); [IO.File]::WriteAllBytes((Join-Path $sd 'bigapp/data.bin'), $big)
    $env:SystemRoot = $sr; $env:SystemDrive = $sd
    $copy = Join-Path $tmp 'offbox'; New-Item -ItemType Directory -Path $copy -Force | Out-Null

    T-Start 'a domain controller with IIS, DNS and DHCP (stand-ins)'
    $r = Run @('-Out', $out, '-MaxMB', '1', '-Path', ((Join-Path $sd 'app') + ',' + (Join-Path $sd 'bigapp')), '-CopyTo', $copy)
    $b = $r.Dir
    T-Eq $r.Code 5 'exits 5: GroupPolicy and AD are not available here, so those items fail'
    T-Has $r.Text 'READ-ONLY' 'says it changes nothing on the host'
    T-Eq (Item $b 'registry').status 'ok' 'registry saved'
    T-HasNot (Item $b 'registry').detail 'WOW6432Node' 'a key that does not exist on this box is not a failure'
    T-True (Test-Path -LiteralPath (Join-Path $b 'registry/services.reg')) 'services key exported'
    T-Eq (Item $b 'firewall').status 'ok' 'firewall saved'
    T-Eq (Item $b 'secpolicy').status 'ok' 'security policy saved'
    T-Eq (Item $b 'auditpol').status 'ok' 'audit policy saved'
    T-Eq (Item $b 'tasks').status 'ok' 'tasks saved'
    T-True (Test-Path -LiteralPath (Join-Path $b 'tasks/Updater')) 'a task XML is in the backup'
    T-Eq (Item $b 'hosts').status 'ok' 'hosts saved'
    T-Eq (Item $b 'users').status 'skipped' 'users skipped where there is no WMI'
    T-Eq (Item $b 'iis').status 'ok' 'IIS settings saved'
    T-Has (Item $b 'iis').detail '2 site folders found' 'site folders read from applicationHost.config'
    T-Eq (Item $b 'web').status 'ok' 'website files saved'
    T-True (Test-Path -LiteralPath (Join-Path $b 'web')) 'web folder created'
    $webFiles = @(Get-ChildItem -LiteralPath (Join-Path $b 'web') -Recurse | Where-Object { -not $_.PSIsContainer } | ForEach-Object { $_.Name })
    T-True (($webFiles -contains 'cart.aspx') -and ($webFiles -contains 'index.html')) 'both sites copied'
    T-Eq (Item $b 'dns').status 'ok' 'DNS saved'
    T-Has (Item $b 'dns').detail '2 zones: _msdcs.corp.local, corp.local' 'zones exported (cache and TrustAnchors left out)'
    T-Has (Item $b 'dns').detail 'FAILED: 0.0.10.in-addr.arpa' 'a zone that fails is named'
    T-True (Test-Path -LiteralPath (Join-Path $b 'dns/corp.local.dns')) 'zone file in the backup'
    T-Eq (@(Get-ChildItem -LiteralPath (Join-Path $sr 'System32/dns') -Filter 'ccdc-backup-*').Count) 0 'no export file is left in the DNS folder'
    T-Eq (Item $b 'dhcp').status 'ok' 'DHCP saved'
    T-Eq (Item $b 'gpo').status 'failed' 'GPO fails without the GroupPolicy module (as on a broken DC)'
    T-Eq (Item $b 'sysvol').status 'ok' 'SYSVOL saved'
    T-True (Test-Path -LiteralPath (Join-Path $b 'sysvol/scripts/logon.bat')) 'logon script in the backup'
    T-Eq (Item $b 'addb').status 'skipped' 'AD database not saved unless asked for'
    T-Has (Item $b 'addb').detail 'every password hash' 'and the reason is given'
    T-Eq (Item $b 'paths').status 'ok' '-Path folder saved'
    T-Has (Item $b 'paths').detail 'MB, over -MaxMB' 'a folder over -MaxMB is listed as not saved'
    T-HasNot (ReadF (Join-Path $b 'SHA256SUMS.txt')) 'data.bin' 'and is not in the backup'
    $rs = ReadF (Join-Path $b 'RESTORE.txt')
    T-Has $rs 'reg import "' 'RESTORE: registry'
    T-Has $rs 'netsh advfirewall import "' 'RESTORE: firewall'
    T-Has $rs 'secedit /configure /db "' 'RESTORE: security policy'
    T-Has $rs 'auditpol /restore /file:"' 'RESTORE: audit policy'
    T-Has $rs 'schtasks /create /tn' 'RESTORE: tasks'
    T-Has $rs 'dnscmd /zoneadd corp.local /primary /file corp.local.dns /load' 'RESTORE: DNS zone'
    T-Has $rs 'netsh dhcp server import "' 'RESTORE: DHCP'
    T-Has $rs 'iisreset /stop' 'RESTORE: IIS'
    T-HasNot $rs '## gpo' 'no restore section for an item that failed'
    $sums = @([IO.File]::ReadAllLines((Join-Path $b 'SHA256SUMS.txt')))
    T-True ($sums.Count -ge 15) "every saved file is hashed ($($sums.Count) lines)"
    $first = $sums[0] -split '  ', 2
    $h = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $b $first[1])).Hash.ToLower()  # ps2-ok (test, PowerShell 7)
    T-Eq $first[0] $h 'a hash line matches the file'
    T-Has (ReadF $log) ('icacls.exe ' + $b + ' /inheritance:r') 'the backup folder is limited to Administrators and SYSTEM'
    $dest = Join-Path $copy (Split-Path -Leaf $b)
    T-True (Test-Path -LiteralPath (Join-Path $dest 'RESTORE.txt')) '-CopyTo copied the backup'
    T-True (Test-Path -LiteralPath (Join-Path $dest 'summary.txt')) 'including the summary'
    T-Has $r.Text 'Copied to:' 'the summary says where it went'
    T-Has $r.Text 'saved,' 'summary counts'

    T-Start 'a failure is reported, and -Only'
    $env:FAIL_SECEDIT = '1'
    $r = Run @('-Out', $out, '-Only', 'secpolicy,hosts')
    Remove-Item Env:\FAIL_SECEDIT
    T-Eq $r.Code 5 'a failed item exits 5'
    T-Has (Item $r.Dir 'secpolicy').detail 'access denied' "the program's own message is kept"
    T-Eq (@(Import-Csv -LiteralPath (Join-Path $r.Dir 'items.csv')).Count) 2 '-Only runs just those items'
    $r = Run @('-Out', $out, '-Only', 'registry,firewall,tasks', '-Quiet')
    T-Eq $r.Code 0 'all good exits 0'
    T-HasNot $r.Text 'saved  ' '-Quiet keeps the item list off the screen'
    T-Has $r.Text 'not copied off the box' 'reminds to copy off the box, even with -Quiet'
}

Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
exit 0
