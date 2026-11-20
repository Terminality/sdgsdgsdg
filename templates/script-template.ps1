# =============================================================================
# ID:       XX-00                      <- the ID from docs/catalog.csv
# NAME:     Script template            <- the catalog name
# ROLE:     <official role>  (wave N)
# KIND:     readonly | changes         <- 'changes' if it can modify the system
#
# PURPOSE
#   One or two sentences: what problem this solves during the competition.
#
# USAGE
#   powershell -NoProfile -ExecutionPolicy Bypass -File XX-00-name.ps1 [options]
#
#   QUESTIONS (Enter takes the default in capitals; a parameter answers each):
#     which box                       -Box NAME
#     the example option              -Example VALUE
#
# INPUTS
#   -Example VALUE    what this option means and what happens without it
#   Files read:       e.g. the protected list
#
# OUTPUTS  (all under the -Out folder, never next to the script)
#   <ID>_<host>_<time>.log            everything printed, plus action output
#   undo-<host>.log                   one line per change, newest last
#   example-N\                        one numbered folder per run:
#     output.txt                      the screen, without colours
#     example.txt                     describe each table and its columns
#     run.txt                         id, host, time
#
# WHAT IT CHANGES
#   List every kind of change, or "nothing - read only".
#
# DEPENDS ON
#   Cmdlets and programs used, with the fallback for old systems
#   (Get-NetTCPConnection -> netstat -ano).
#
# TESTED ON
#   List the Windows and PowerShell versions it has really been run on.
#   Leave "not yet tested" until it has.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   Anything an operator must know before trusting the output.
#
# DEBUGGING
#   -DebugLog shows each decision.  Set-PSDebug -Trace 1 shows each line.
#   The log file has the output of every action run through Invoke-CcChange.
# =============================================================================
param(
    # Common parameters: every script declares exactly these seven.
    [switch]$Apply,          # make changes (default is a dry run)
    [string]$Out,            # folder for logs, CSV files, backups, undo log
    [string]$Protected,      # protected-list CSV
    [switch]$NoProtected,    # allow -Apply without a protected list (dangerous)
    [switch]$ForceScored,    # allow changes to accounts on the protected list
    [switch]$Quiet,          # only print warnings and errors
    [switch]$DebugLog,       # print debugging detail
    [switch]$Batch,          # no questions: take every default
    [switch]$NoColor,        # no colours
    # This script's own parameters (each one answers a question):
    [string]$Box,
    [string]$Example
)

# >>> BT-LIB
# Development copy: find lib/lib.ps1 by walking up from this file.  The build
# step (tools/build.sh, LB-03) replaces this whole block with the library
# itself, so the built script is a single standalone file.
$ccDir = Split-Path -Parent $MyInvocation.MyCommand.Path
while ($ccDir -and -not (Test-Path -LiteralPath (Join-Path (Join-Path $ccDir 'lib') 'lib.ps1'))) { $ccDir = Split-Path -Parent $ccDir }
if (-not $ccDir) { Write-Host 'cannot find lib/lib.ps1 above this script'; exit 3 }
. (Join-Path (Join-Path $ccDir 'lib') 'lib.ps1')
# <<< BT-LIB

# ---- 1. Start: open the log, find the protected list, check the kit --------
if (-not (Test-CcBox $Box)) { Stop-Cc -Code 2 -Message ('-Box must be one of: ' + ($script:CcBoxes -join ' ')) }
Initialize-Cc -Id 'XX-00' -Name 'Script template' -Kind readonly -Bound $PSBoundParameters
$os = Get-CcOsInfo
# Assert-CcAdmin           # uncomment if the script needs an elevated session
Use-CcNumberedDir 'example'

# The look: a title line, the legend, then numbered sections.
Write-CcShow -Color Cyan -Text ('XX-00 Script template | host {0} | results in {1}' -f $script:Cc.Host, $script:Cc.RunDir)
Write-CcLegend

# ---- 2. The questions: each one answered in advance by its parameter -------
Write-CcHeader '1/2  questions'
if (-not $Box) { $Box = Read-CcBox }
if (-not $Example) { $Example = Read-CcText -Question 'An example option?' -Default 'default' -Hint 'any word' }

# ---- 3. The work ------------------------------------------------------------
# Scripts that change things call Test-CcAllowed before touching an item,
# Backup-CcFile or Backup-CcRegistryKey before editing, make every change
# through Invoke-CcChange (dry run and undo are automatic), and wrap risky
# changes in Start-CcTimer ... Complete-CcTimer.
Write-CcHeader '2/2  the work'
$t = New-CcTable -Name example -Columns @('item', 'value')
Add-CcTableRow -File $t -Values @('powershell version', $os.PSVersion)
Add-CcTableRow -File $t -Values @('box', $Box)
Add-CcTableRow -File $t -Values @('example option', $Example)
Format-CcTable -File $t
Write-CcShow -Color Green -Text ('  [ok] wrote ' + $t)

# ---- 4. Finish: print the summary and exit with the right code -------------
Complete-Cc
