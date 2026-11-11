#!/bin/sh
# =============================================================================
# tests/lint-ps2.sh - catch PowerShell that will not run on PowerShell 2.0.
#
# WHY   The Windows scripts must run on Server 2008 R2 / Windows 7 (PowerShell
#       2.0) through current versions.  We cannot run 2.0 on a build machine,
#       so this search flags the cmdlets and syntax added after 2.0.
# HOW   Searches every .ps1 file under the repo (except dist/).  Comment lines
#       are skipped.  A line that uses a newer feature safely - for example
#       inside "if (Get-Command Get-NetTCPConnection ...)" with an older
#       fallback beside it - can be excused by ending it with:   # ps2-ok
# USAGE sh tests/lint-ps2.sh              exit 0 = clean, 1 = problems listed
# NOTE  This is a pattern search, not a parser, and it runs anywhere (it does
#       not need PowerShell).  It does not replace running the scripts on a
#       real 2.0 machine.
# =============================================================================
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
bad=0
check() {
    hits=$(find . -name '*.ps1' -not -path './dist/*' -not -path './.git/*' -exec grep -niE -- "$2" {} + 2>/dev/null \
        | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' | grep -v 'ps2-ok')
    if [ -n "$hits" ]; then
        bad=1
        printf 'NOT PowerShell 2.0 - %s\n%s\n\n' "$1" "$hits"
    fi
}
check "JSON cmdlets arrived in 3.0; write CSV"                         'Convert(To|From)-Json'
check "[pscustomobject] arrived in 3.0; use New-Object PSObject -Property @{}" '\[pscustomobject\]'
check "[ordered] arrived in 3.0"                                      '\[ordered\]'
check "CIM cmdlets arrived in 3.0; use Get-WmiObject"                 '(Get|New|Invoke|Set|Remove)-Cim[A-Z]'
check "\$PSScriptRoot / \$PSCommandPath arrived in 3.0; use Split-Path -Parent \$MyInvocation.MyCommand.Path" '\$PS(ScriptRoot|CommandPath)'
check "-in / -notin arrived in 3.0; use -contains"                    '[[:space:]]-(not)?in[[:space:]]'
check ".Where() / .ForEach() arrived in 4.0; use Where-Object / ForEach-Object" '\.(Where|ForEach)\('
check "Get-FileHash arrived in 4.0; use Get-CcSha256"                 'Get-FileHash'
check "Export-Csv -Append arrived in 3.0; use Add-CcCsvRow"           'Export-Csv[^|]*-Append'
check "Net*/Local*/ScheduledTask/Dns cmdlets need Server 2012+; use netsh, net.exe, schtasks, WMI" '(Get|Set|New|Remove|Enable|Disable)-(Net[A-Z]|Local(User|Group)|ScheduledTask|SmbShare|SmbServer|MpPreference|MpComputer|DnsServer|DnsClient)'
check "web cmdlets arrived in 3.0; use (New-Object Net.WebClient)"    'Invoke-(RestMethod|WebRequest)'
check "write [Parameter(Mandatory=\$true)] - the short form is a 2.0 syntax error" 'Mandatory[[:space:]]*[,)]'
check "Get-ChildItem -File / -Directory arrived in 3.0; filter on PSIsContainer" 'Get-ChildItem[^|#]*-(File|Directory)([[:space:]]|$)'
check "::new() arrived in 5.0; use New-Object"                        '::new\('
check "'using namespace' and classes arrived in 5.0"                  '^[[:space:]]*(using[[:space:]]+namespace|class[[:space:]]+[A-Za-z]+[[:space:]]*\{)'
check "IsNullOrWhiteSpace needs .NET 4; use IsNullOrEmpty after .Trim()" 'IsNullOrWhiteSpace'
check "Resolve-DnsName / Test-NetConnection need Server 2012+"        '(Resolve-DnsName|Test-NetConnection)'
check "-shl / -shr arrived in 3.0"                                    '[[:space:]]-sh[lr][[:space:]]'
check "Start-Process -PassThru ... .ExitCode is fine, but 'Unblock-File' arrived in 3.0" 'Unblock-File'
[ "$bad" -eq 0 ] && echo "lint-ps2: clean"
exit "$bad"
