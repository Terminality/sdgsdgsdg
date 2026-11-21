# =============================================================================
# ID:       WN-50
# NAME:     Windows service recovery (find out why a service is down, bring it back)
# ROLE:     Windows / AD  (any time a scored service goes red)
# KIND:     changes - dry run unless -Apply
# VERSION:  1.0.0
#
# PURPOSE
#   When a scored service goes down, starting it again often is not enough:
#   red team broke something under it.  This checks each service the same
#   way, finds the reason, and offers the fix.  The Windows twin of SV-50.
#
#     web       IIS (W3SVC, WAS), Apache, nginx; IIS sites and app pools
#     database  SQL Server, MySQL, MariaDB
#     domain    NTDS, DNS, Kerberos (Kdc), Netlogon, W32Time, ADWS, DFSR
#     others    RDP (TermService), file sharing (LanmanServer), WinRM, FTP,
#               the event log, and every service on the protected list
#
#   For each one that is installed:
#     1  running?        stopped, or disabled (will not start at all)
#     2  its program?    missing, or in a temp or user folder (WN-42)
#     3  port?           listening; or ANOTHER program holds the port
#     4  answers?        a connection to the port; a web page under 500
#     5  firewall?       an inbound block rule on its port
#     6  crash restart?  set to restart by itself when it crashes
#   IIS: a stopped site or app pool (a favourite: the service runs, the
#   site does not).  Once for the box: the system drive almost full.
#
#   Fixes offered (each asked, yes/no): turn off the block rule, stop the
#   program holding the port, set "starts at boot" (Automatic) when
#   disabled, start or restart, start the site or app pool, restart on
#   crash.  Each fixed service is checked again.
#
#   -Watch checks every N seconds and prints a line the moment a service
#   goes down or comes back; with -AutoRestart -Apply it also starts a
#   service that went down (at most 3 times in 10 minutes each, so a crash
#   loop is not hidden).
#
#   No revert timer: these fixes bring services UP; undoing them would take
#   them down again.  Each change still has an undo line (revert.ps1).
#
#   QUESTIONS (Enter takes the default in capitals; a parameter answers each):
#     which box                       -Box NAME (guessed)
#     which services                  -Services a,b (Enter = all found)
#     each fix (yes / no)             -Fix KINDS (always yes for these kinds)
#     apply these fixes?              -Apply (Enter = no: a dry run)
#
# USAGE
#   powershell -NoProfile -ExecutionPolicy Bypass -File WN-50-service-recovery.ps1               check, dry run
#   powershell ... WN-50-service-recovery.ps1 -Apply                                            check and fix (asks)
#   powershell ... WN-50-service-recovery.ps1 -Apply -Batch -Services W3SVC,DNS
#   powershell ... WN-50-service-recovery.ps1 -Watch 30 -AutoRestart -Apply
#   Run in an elevated window.
#
# OPTIONS
#   -Box NAME          dc | web | ecomm | fileshare | db | other (asked)
#   -Services a,b      only these services (their names, e.g. W3SVC,DNS)
#   -Fix KINDS         answer yes for these fix kinds: firewall kill enable
#                      start pool recovery (default: each asked; -Batch
#                      takes the default shown)
#   -Watch SECONDS     keep checking; print changes (Ctrl-C to stop)
#   -AutoRestart       with -Watch and -Apply: start what goes down
#   -WatchCount N      with -Watch: stop after N rounds (tests)
#   -Batch             no questions: the defaults (a dry run unless -Apply)
#   -NoColor           no colours
#   Common options (-Apply, -Out, -Protected, -NoProtected, -ForceScored,
#   -Quiet, -DebugLog) come from the library.
#
# OUTPUTS  (under -Out, one numbered folder per run: recovery-1, -2, ...)
#   output.txt   everything shown on screen, without colour
#   status.txt   each service: state, start, port, answer, problems
#   summary.txt, run.txt, undo.txt, revert.ps1;  watch.txt with -Watch
#
# DEPENDS ON
#   WMI (Win32_Service), netstat.exe, sc.exe, netsh.exe, the firewall COM
#   object (HNetCfg.FwPolicy2), appcmd.exe for IIS: Windows 7 / Server
#   2008 R2 and later.  $env:BT_WN50_FAKE names a folder of stand-in state
#   for the tests: then nothing real is read or changed.
#
# TESTED ON
#   PowerShell 7 on Linux against stand-in state (tests/wn50.Tests.ps1).
#   NOT yet run on real Windows: run it on a throwaway VM first.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - "Up" here means it answers on this box.  If scoring still fails,
#     check the firewall between (WN-25, the router) and the scoring address.
#   - A defaced site answers 200: look at the page yourself; WN-16 for shells.
#   - A firewall rule is turned off by name: rules sharing that name are
#     turned off together.
#
# DEBUGGING
#   -DebugLog shows each check.  status.txt holds every result.
# =============================================================================
param(
    [switch]$Apply, [string]$Out, [string]$Protected, [switch]$NoProtected,
    [switch]$ForceScored, [switch]$Quiet, [switch]$DebugLog,
    [string]$Box = '',
    [string[]]$Services = @(),
    [string[]]$Fix = @(),
    [int]$Watch = 0,
    [switch]$AutoRestart,
    [int]$WatchCount = 0,
    [switch]$Help,
    [switch]$Batch,
    [switch]$NoColor
)

if ($Help) {
    Write-Host 'WN-50 Windows service recovery - why a service is down, and the fix'
    Write-Host '  -Box NAME       dc web ecomm fileshare db other (asked; guessed)'
    Write-Host '  -Services a,b   only these (Enter = all found)'
    Write-Host '  -Fix KINDS      yes for these: firewall kill enable start pool recovery'
    Write-Host '  -Watch SECONDS  keep checking   -AutoRestart (with -Apply)   -WatchCount N'
    Write-Host '  -Batch -NoColor -Apply -Out DIR -Protected FILE -NoProtected -Quiet -DebugLog'
    exit 0
}

# >>> BT-LIB  (lib/lib.ps1 0.7.0 pasted in by tools/build.sh - edit lib/lib.ps1, not this copy)
# =============================================================================
# ID:       LB-02
# NAME:     PowerShell library (lib.ps1)
# ROLE:     Automation  (wave 0, foundation)
# VERSION:  0.7.0
#
# PURPOSE
#   The jobs every Windows script in this kit repeats, written once.  It is the
#   twin of lib/lib.sh and behaves the same way on purpose:
#     1. common parameters                  Initialize-Cc
#     2. dry-run by default / apply mode    Invoke-CcChange, Invoke-CcProgram
#     3. log naming and log lines           Write-CcLog
#     4. backup + one undo log per host     Backup-CcFile, Backup-CcRegistryKey,
#                                           Add-CcUndo
#     5. the protected-list refusal         Test-CcProtected, Test-CcAllowed
#     6. meaningful exit codes              Stop-Cc, Complete-Cc
#     7. the look and the questions         Write-CcShow, Write-CcHeader,
#        (the same as lib.sh)               Write-CcLegend, Read-CcChoice,
#                                           Read-CcAsk, Read-CcText, Read-CcBox
#     8. numbered run folders, .txt tables  Use-CcNumberedDir, New-CcTable
#     9. the revert timer                   Start-CcTimer, Complete-CcTimer
#   plus: admin check, OS facts, password generation, quarantine, SHA-256,
#   CSV output, findings files, and for inventory scripts: flags
#   (Add-CcFlag), a per-run folder (Use-CcRunDir) and raw command capture
#   (Save-CcOutput).
#
# HOW A SCRIPT USES IT
#   Start every new script from templates/script-template.ps1.  A script
#   declares the common parameters, loads the library through the marker
#   block, and hands its bound parameters to Initialize-Cc.
#   tools/build.sh replaces the marker block with this file's contents so every
#   built script in dist/ is one standalone file.
#
#       param(
#           [switch]$Apply, [string]$Out, [string]$Protected, [switch]$NoProtected,
#           [switch]$ForceScored, [switch]$Quiet, [switch]$DebugLog,
#           [string]$MyOwnOption
#       )
#       # >>> BT-LIB
#       ...the loader lines from templates/script-template.ps1...
#       # <<< BT-LIB
#       Initialize-Cc -Id 'WN-99' -Name 'Example script' -Kind changes -Bound $PSBoundParameters
#       Invoke-CcChange -Description 'stop Telnet' -Action { Stop-Service TlntSvr } `
#                       -Undo 'Start-Service TlntSvr' | Out-Null
#       Complete-Cc
#
# LANGUAGE RULES (why this file avoids newer PowerShell)
#   Everything here must run on PowerShell 2.0 (Server 2008 R2 / Windows 7)
#   through current versions.  So this file does NOT use:
#     ConvertTo-Json / ConvertFrom-Json, [pscustomobject], [ordered],
#     Get-CimInstance (WMI via Get-WmiObject instead), $PSScriptRoot,
#     the -in / -notin operators, .Where() / .ForEach(), Get-FileHash,
#     Export-Csv -Append, or Get-Net* / Get-Local* cmdlets.
#   [Parameter(Mandatory=$true)] is always written with '=$true'; the short
#   form is a syntax error on 2.0.  Results that might be one item or none are
#   wrapped in @( ) before .Count is read, because 2.0 has no .Count on a
#   single object.  tests/lint-ps2.sh checks these rules mechanically.
#
# DEBUGGING
#   -DebugLog              print DEBUG lines (paths, decisions, tool choices)
#   Set-PSDebug -Trace 1   trace every line PowerShell runs
#   Every run writes  <out>\<ID>_<host>_<UTC time>.log  with everything printed
#   plus the output of every action run through Invoke-CcChange.
#   If a script will not start at all: "running scripts is disabled" means the
#   execution policy blocked it; start it with
#       powershell -NoProfile -ExecutionPolicy Bypass -File script.ps1 ...
#
# EXIT CODES (identical to lib.sh)
#   0  finished; nothing failed
#   1  unexpected error
#   2  usage error
#   3  missing requirement (not admin, no protected list, kit check failed)
#   4  refused: the only thing asked for is on the protected list
#   5  finished, but at least one change failed (see the log)
#
# KNOWN LIMITS
#   - Tested here only on PowerShell 7 (Linux) plus the 2.0 lint.  It has NOT
#     yet been run on real PowerShell 2.0, 4.0 or 5.1; do that on the test VMs
#     before trusting it.
#   - Test-CcSelf cannot check a script that was pasted or piped into the
#     session, because there is no file to hash.
# =============================================================================

$script:CcLibVersion = '0.7.0'

# All library state lives in one hashtable so it is easy to inspect while
# debugging: type  $Cc  at a prompt after dot-sourcing a script.
$script:Cc = @{
    Id = 'CC-00'; Name = ''; Kind = 'readonly'
    Apply = $false; Quiet = $false; DebugLog = $false
    ForceScored = $false; NoProtected = $false
    Out = $null; Log = $null; Undo = $null; BackupDir = $null; QuarDir = $null
    Protected = $null; ProtectedRows = $null; Findings = $null
    Host = $null; Ts = $null; Kit = $null; ScriptPath = $null
    Done = 0; Would = 0; Failed = 0; Refused = 0; FindingCount = 0
    RunDir = $null; CsvDir = $null; FlagsFile = $null; FlagCount = 0
    Batch = $false; NoColor = $false; Tee = $null; Work = $null; Numbered = $false; RunUndo = $null
    Answers = $null; AnswersUsed = $false; TimerTask = $null; TimerAt = $null
}

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------

# Write-CcLog -Level INFO -Message 'text'
#   One line to the screen and to the log file.  Before Initialize-Cc has
#   opened the log, lines go to the screen only.
#   NEVER pass a password to this function: the log file is shared.
function Write-CcLog {
    param([string]$Level = 'INFO', [string]$Message)
    $line = '{0} [{1}] {2}: {3}' -f ([DateTime]::UtcNow.ToString("HH:mm:ss'Z'")), $Level, $script:Cc.Id, $Message
    $show = $true
    $color = 'Gray'
    if ($Level -eq 'DEBUG') { $show = $script:Cc.DebugLog; $color = 'DarkGray' }
    elseif ($Level -eq 'WARN') { $color = 'Yellow' }
    elseif ($Level -eq 'ERROR' -or $Level -eq 'REFUSED') { $color = 'Red' }
    elseif ($Level -eq 'DO') { $color = 'Green' }
    elseif ($Level -eq 'WOULD' -or $Level -eq 'FINDING') { $color = 'Cyan' }
    elseif ($Level -eq 'NOTE') { $show = $false }     # log file only: detail that would flood the screen
    elseif ($script:Cc.Quiet) { $show = $false }
    if ($show) { Write-Host $line -ForegroundColor $color }
    if ($script:Cc.Log) {
        try { [IO.File]::AppendAllText($script:Cc.Log, $line + "`r`n") } catch { }
    }
    if ($script:Cc.Tee -and $Level -ne 'DEBUG' -and $Level -ne 'NOTE') {
        try { [IO.File]::AppendAllText($script:Cc.Tee, $line + "`r`n") } catch { }
    }
}

# Stop-Cc -Code 3 -Message 'why'
#   Log an error and end the script with that exit code.
function Stop-Cc {
    param([int]$Code = 1, [string]$Message)
    Write-CcLog -Level ERROR -Message $Message
    exit $Code
}

# -----------------------------------------------------------------------------
# Small helpers
# -----------------------------------------------------------------------------

# Test-CcCommand name   -> $true if a command, cmdlet or program exists.
function Test-CcCommand {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

# ConvertTo-CcQuoted text   -> the text in single quotes, safe to paste into
#   PowerShell.  Used to build the undo commands.
function ConvertTo-CcQuoted {
    param([string]$Text)
    return "'" + ($Text -replace "'", "''") + "'"
}

# Resolve-CcPath path   -> absolute path, whether or not it exists yet.
function Resolve-CcPath {
    param([string]$Path)
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

# Test-CcWindows   -> $true on Windows.  False only when the tests run the
#   library under PowerShell 7 on Linux.
function Test-CcWindows {
    return ([Environment]::OSVersion.Platform -eq 'Win32NT')
}

# Test-CcAdmin     -> $true when the session is elevated.
function Test-CcAdmin {
    if (-not (Test-CcWindows)) { return $false }
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Assert-CcAdmin   -> stop with exit 3 unless elevated.
function Assert-CcAdmin {
    if (-not (Test-CcAdmin)) {
        Stop-Cc -Code 3 -Message 'this script must run in an elevated (Run as administrator) PowerShell window'
    }
}

# Confirm-Cc 'question'   -> ask the operator; $true for yes.
#   $env:BT_ASSUME_YES = '1' answers yes without asking (for fan-out).
function Confirm-Cc {
    param([string]$Question)
    if ($env:BT_ASSUME_YES -eq '1') { return $true }
    $a = Read-Host ($Question + ' [y/N]')
    return ($a -eq 'y' -or $a -eq 'yes')
}

# Get-CcOsInfo   -> hashtable of facts scripts branch on:
#   Caption, Version, Build, ProductType (1 workstation, 2 domain controller,
#   3 member server), IsDC, IsServer, Is64Bit, PSVersion (major number).
#   Uses WMI because Get-CimInstance does not exist on PowerShell 2.0.
function Get-CcOsInfo {
    $info = @{ Caption = 'unknown'; Version = ''; Build = ''; ProductType = 0
               IsDC = $false; IsServer = $false; Is64Bit = ([IntPtr]::Size -eq 8)
               PSVersion = $PSVersionTable.PSVersion.Major }
    if (Test-CcWindows) {
        try {
            $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
            $info.Caption = $os.Caption; $info.Version = $os.Version; $info.Build = $os.BuildNumber
            $info.ProductType = [int]$os.ProductType
            $info.IsDC = ($info.ProductType -eq 2); $info.IsServer = ($info.ProductType -ne 1)
        } catch {
            Write-CcLog -Level WARN -Message ('could not read OS details from WMI: ' + $_.Exception.Message)
        }
    }
    Write-CcLog -Level DEBUG -Message ('os: {0} build {1} type {2} ps {3}' -f $info.Caption, $info.Build, $info.ProductType, $info.PSVersion)
    return $info
}

# -----------------------------------------------------------------------------
# The look and the questions (the same as lib.sh)
# -----------------------------------------------------------------------------
# Every script looks and asks the same way on Windows and on Linux:
#     ==========[ 2/6  accounts ]==========          Write-CcHeader
#     Legend: [!] HIGH  [*] MED  [ok] fine ...          Write-CcLegend
#     [?] Which box is this?                            Read-CcChoice, Read-CcAsk,
#           [d] domain controller (AD, DNS)             Read-CcText, Read-CcBox
#           [o] other
#           Answer [d/O]:
# Enter takes the default (the answer in capitals).  With -Batch, or with no
# console to ask on, every default is taken and shown.  Each question has a
# script parameter that answers it in advance.
# Results go in a numbered folder per run (Use-CcNumberedDir): <out>\NAME-1,
# NAME-2, ... with output.txt (the screen without colour), run.txt and .txt
# tables (New-CcTable).  No CSV is left in it.

# Write-CcShow -Color Red -Text '...'   -> the text on screen in that colour
#   (Red, Yellow, Green, Cyan, DarkGray, or '' for plain) and a plain copy in
#   output.txt.
function Write-CcShow {
    param([string]$Color = '', [string]$Text = '')
    # -Quiet: only warnings and errors on screen (output.txt still gets it all).
    if (-not $script:Cc.Quiet) { if ($Color -and -not $script:Cc.NoColor) { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text } }
    if ($script:Cc.Tee) { try { [IO.File]::AppendAllText($script:Cc.Tee, $Text + "`r`n") } catch { } }
}

# Write-CcHeader 'title'   -> a blank line, then ==========[ title ]==========
function Write-CcHeader {
    param([string]$Title)
    Write-CcShow -Text ''
    Write-CcShow -Color Cyan -Text ('==========[ {0} ]==========' -f $Title)
}

# Write-CcLegend   -> the legend line, each mark in its colour.
#   -Marks takes other pairs: @('Red=[!] DOWN','Green=[ok] up').
function Write-CcLegend {
    param([string[]]$Marks = @('Red=[!] HIGH', 'Yellow=[*] MED', 'Green=[ok] fine', 'Yellow=[~] would change', 'Green=[+] changed', 'Red=[x] failed'))
    $q = $script:Cc.Quiet
    if (-not $q) { Write-Host 'Legend: ' -NoNewline }
    $plain = 'Legend:'
    foreach ($m in $Marks) {
        $p = $m -split '=', 2
        if (-not $q) { if ($script:Cc.NoColor) { Write-Host ($p[1] + '   ') -NoNewline } else { Write-Host ($p[1] + '   ') -ForegroundColor $p[0] -NoNewline } }
        $plain = $plain + ' ' + $p[1] + '  '
    }
    if (-not $q) { Write-Host '' }
    if ($script:Cc.Tee) { try { [IO.File]::AppendAllText($script:Cc.Tee, $plain.TrimEnd() + "`r`n") } catch { } }
}

# Test-CcCanAsk   -> $true when questions can be asked: not -Batch, not
#   $env:BT_NO_TTY = '1', and a console to read from (or test answers).
function Test-CcCanAsk {
    $c = $script:Cc
    if ($c.Batch -or $env:BT_NO_TTY -eq '1') { return $false }
    if ($null -ne $c.Answers -and $c.Answers.Count -gt 0) { return $true }
    if (-not [Environment]::UserInteractive) { return $false }
    # Started with -NonInteractive (a scheduled task, a test): Read-Host would fail.
    foreach ($a in [Environment]::GetCommandLineArgs()) { if ($a -match '^-noni') { return $false } }
    if ($Host.Name -eq 'Windows PowerShell ISE Host') { return $true }
    try { [void][Console]::KeyAvailable; return $true } catch { return $false }
}

# Read-CcLine 'prompt'   -> one typed line.  Tests feed the answers in
#   $env:BT_TEST_ANSWERS, separated by ';' (read once at start-up).
function Read-CcLine {
    param([string]$Prompt)
    $c = $script:Cc
    if ($null -ne $c.Answers -and $c.Answers.Count -gt 0) {
        $a = [string]$c.Answers[0]
        $c.Answers.RemoveAt(0)
        Write-Host ($Prompt + ': ' + $a)
        return $a
    }
    if ($c.AnswersUsed) { Write-Host ($Prompt + ': '); return '' }   # tests ran out of answers: take the default
    return [string](Read-Host -Prompt $Prompt)
}

# Read-CcChoice -Question 'Which box is this?' -Default o -Options @('d=domain controller','o=other')
#   -> the letter chosen.  Each option is 'letter=what it means'.
function Read-CcChoice {
    param([Parameter(Mandatory=$true)][string]$Question, [string]$Default = '', [Parameter(Mandatory=$true)][string[]]$Options)
    $d = $Default.ToLower(); $keys = @(); $hint = @(); $mean = ''
    foreach ($o in $Options) {
        $p = $o -split '=', 2
        $keys += $p[0]
        if ($p[0] -eq $d) { $hint += $p[0].ToUpper(); $mean = $p[1] } else { $hint += $p[0] }
    }
    $h = $hint -join '/'
    if (-not (Test-CcCanAsk)) {
        Write-CcShow -Color Cyan -Text ('[?] {0} [{1}] {2} (default): {3}' -f $Question, $h, $d, $mean)
        Write-CcLog -Level NOTE -Message ('asked: {0} -> {1} (default)' -f $Question, $d)
        return $d
    }
    if ($script:Cc.NoColor) { Write-Host '[?] ' -NoNewline } else { Write-Host '[?] ' -ForegroundColor Cyan -NoNewline }
    Write-Host $Question
    foreach ($o in $Options) { $p = $o -split '=', 2; Write-Host ('      [{0}] {1}' -f $p[0], $p[1]) }
    $a = ''; $tries = 0
    while ($true) {
        $a = (Read-CcLine -Prompt ('      Answer [' + $h + ']')).Trim().ToLower()
        if ($a -eq '') { $a = $d }
        if ($a -ne '' -and $keys -contains $a) { break }
        $tries++
        if ($tries -ge 5 -and $d) { $a = $d; break }
        Write-Host ('      Type one of: ' + ($keys -join ', ')) -ForegroundColor Yellow
    }
    if ($script:Cc.Tee) { try { [IO.File]::AppendAllText($script:Cc.Tee, ('[?] {0} {1}' -f $Question, $a) + "`r`n") } catch { } }
    Write-CcLog -Level NOTE -Message ('asked: {0} -> {1}' -f $Question, $a)
    return $a
}

# Read-CcAsk -Question 'Back up the site?' -Default Y [-Yes 'yes, back it up'] [-No 'no, skip it']
#   -> $true for yes.  Shown like Read-CcChoice with what each answer does.
function Read-CcAsk {
    param([Parameter(Mandatory=$true)][string]$Question, [string]$Default = 'N', [string]$Yes = 'yes', [string]$No = 'no')
    $d = 'n'; if ($Default -eq 'Y' -or $Default -eq 'y') { $d = 'y' }
    return ((Read-CcChoice -Question $Question -Default $d -Options @(('y=' + $Yes), ('n=' + $No))) -eq 'y')
}

# Read-CcSecret 'prompt'   -> a typed secret, not shown, never logged and never
#   copied to output.txt.  Tests feed it through $env:BT_TEST_ANSWERS like any
#   other answer.
function Read-CcSecret {
    param([string]$Prompt)
    $c = $script:Cc
    if ($null -ne $c.Answers -and $c.Answers.Count -gt 0) { $a = [string]$c.Answers[0]; $c.Answers.RemoveAt(0); Write-Host ($Prompt + ': (hidden)'); return $a }
    $ss = Read-Host -Prompt $Prompt -AsSecureString
    $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}

# Read-CcText -Question 'Your team addresses?' -Default '' [-Hint 'addresses separated by spaces']
#   -> the typed text, or the default on Enter, -Batch or no console.
function Read-CcText {
    param([Parameter(Mandatory=$true)][string]$Question, [string]$Default = '', [string]$Hint = '')
    $shown = $Default; if (-not $shown) { $shown = 'none' }
    if (-not (Test-CcCanAsk)) {
        Write-CcShow -Color Cyan -Text ('[?] {0} {1} (default)' -f $Question, $shown)
        return $Default
    }
    if ($script:Cc.NoColor) { Write-Host '[?] ' -NoNewline } else { Write-Host '[?] ' -ForegroundColor Cyan -NoNewline }
    Write-Host $Question
    if ($Hint) { Write-Host ('      type: ' + $Hint) }
    $a = (Read-CcLine -Prompt ('      [Enter = ' + $shown + ']')).Trim()
    if ($a -eq '') { $a = $Default }
    if ($script:Cc.Tee) { try { [IO.File]::AppendAllText($script:Cc.Tee, ('[?] {0} {1}' -f $Question, $a) + "`r`n") } catch { } }
    return $a
}

# The Windows box kinds (-Box NAME and the question), and the guess.
$script:CcBoxes = @('dc', 'web', 'ecomm', 'fileshare', 'db', 'other')
# Test-CcBox NAME   -> $true for '' or a known box kind.
function Test-CcBox {
    param([string]$Name)
    return ([string]::IsNullOrEmpty($Name) -or ($script:CcBoxes -contains $Name.ToLower()))
}
# Get-CcBoxGuess   -> @(kind, why) from what is installed; @('', '') when
#   nothing points anywhere.  Only reads.  Tests: $env:BT_TEST_BOX_GUESS =
#   'web|IIS' (that guess) or '-' (no guess).
function Get-CcBoxGuess {
    if ($env:BT_TEST_BOX_GUESS -eq '-') { return @('', '') }
    if ($env:BT_TEST_BOX_GUESS) { $p = $env:BT_TEST_BOX_GUESS -split '\|', 2; return @($p[0], $p[1]) }
    if (-not (Test-CcWindows)) { return @('', '') }
    try {
        $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        if ([int]$os.ProductType -eq 2) { return @('dc', 'a domain controller') }
    } catch { }
    $names = @(Get-Service -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    if ($names -contains 'W3SVC') { return @('web', 'IIS is installed (W3SVC)') }
    foreach ($n in $names) { if ($n -eq 'MSSQLSERVER' -or $n -like 'MSSQL$*') { return @('db', ('SQL Server (' + $n + ')')) } }
    try {
        $sh = @(Get-WmiObject -Class Win32_Share -ErrorAction Stop | Where-Object { $_.Type -eq 0 -and $_.Name -notmatch '^(ADMIN\$|IPC\$|[A-Z]\$|print\$|NETLOGON|SYSVOL)$' })
        if ($sh.Count -gt 0) { return @('fileshare', ('shared folders: ' + (($sh | ForEach-Object { $_.Name }) -join ' '))) }
    } catch { }
    return @('', '')
}
# Read-CcBox [-Default o] [-Question '...']   -> the box kind.  The guess is
#   shown and becomes the answer for Enter.  A plain IIS guess does not
#   replace a script's own 'ecomm' default.
function Read-CcBox {
    param([string]$Default = 'o', [string]$Question = 'Which box is this?')
    $g = Get-CcBoxGuess
    $d = $Default
    if ($g[0]) {
        Write-CcShow -Color DarkGray -Text ('  This box looks like: {0} ({1})' -f $g[0], $g[1])
        $letter = @{ dc = 'd'; web = 'b'; ecomm = 'e'; fileshare = 'f'; db = 's'; other = 'o' }[$g[0]]
        if (-not ($g[0] -eq 'web' -and $Default -eq 'e')) { $d = $letter }
    }
    $a = Read-CcChoice -Question $Question -Default $d -Options @('d=domain controller (AD, DNS)', 'b=web: an IIS site', 'e=ecomm: a shop or ordering site', 'f=fileshare: shared folders', 's=database: SQL Server', 'o=other')
    return @{ d = 'dc'; b = 'web'; e = 'ecomm'; f = 'fileshare'; s = 'db'; o = 'other' }[$a]
}

# Use-CcNumberedDir 'name'   -> <out>\name-1, name-2, ... (next free number).
#   Creates run.txt (id, host, time) and output.txt, which gets every screen
#   line from now on.  Work files go in <run folder>\.work (removed at the end).
function Use-CcNumberedDir {
    param([Parameter(Mandatory=$true)][string]$Name)
    $c = $script:Cc
    $max = 0
    foreach ($d in @(Get-ChildItem -LiteralPath $c.Out -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer })) {
        if ($d.Name -match ('^' + [regex]::Escape($Name) + '-(\d+)$')) { $n = [int]$matches[1]; if ($n -gt $max) { $max = $n } }
    }
    $n = $max + 1
    while (Test-Path -LiteralPath (Join-Path $c.Out ($Name + '-' + $n))) { $n++ }
    $c.RunDir = Join-Path $c.Out ($Name + '-' + $n)
    try { New-Item -ItemType Directory -Path (Join-Path $c.RunDir '.work') -Force -ErrorAction Stop | Out-Null }
    catch { Stop-Cc -Code 3 -Message ('cannot create run folder {0}: {1}' -f $c.RunDir, $_.Exception.Message) }
    $c.Work = Join-Path $c.RunDir '.work'
    $c.CsvDir = $c.Work
    $c.Numbered = $true
    $c.RunUndo = Join-Path $c.RunDir 'undo.txt'
    [IO.File]::WriteAllText((Join-Path $c.RunDir 'run.txt'), ("id={0}`r`nhost={1}`r`ntime={2}`r`n" -f $c.Id, $c.Host, $c.Ts))
    # output.txt starts with the log so far (the start line), without DEBUG and NOTE lines.
    $c.Tee = Join-Path $c.RunDir 'output.txt'
    $lines = @()
    if ($c.Log -and (Test-Path -LiteralPath $c.Log)) { $lines = @(Get-Content -LiteralPath $c.Log | Where-Object { $_ -notmatch '\[(DEBUG|NOTE)\]' }) }
    [IO.File]::WriteAllText($c.Tee, (($lines -join "`r`n") + $(if ($lines.Count) { "`r`n" } else { '' })))
    Write-CcLog -Level DEBUG -Message ('run folder: ' + $c.RunDir)
}

# New-CcTable -Name accounts -Columns @('account','admin','enabled')
#   -> the path of <run folder>\accounts.txt, a " | " table with that header.
#   Add-CcTableRow adds a line; Format-CcTable pads the columns at the end.
function New-CcTable {
    param([Parameter(Mandatory=$true)][string]$Name, [Parameter(Mandatory=$true)][string[]]$Columns)
    $c = $script:Cc
    if ($c.RunDir) { $f = Join-Path $c.RunDir ($Name + '.txt') } else { $f = Join-Path $c.Out ('{0}_{1}_{2}_{3}.txt' -f $c.Id, $c.Host, $c.Ts, $Name) }
    [IO.File]::WriteAllText($f, (ConvertTo-CcTableLine -Values $Columns) + "`r`n")
    return $f
}
# ConvertTo-CcTableLine @('a','b')   -> 'a | b' ("|" in a value becomes "/").
function ConvertTo-CcTableLine {
    param([object[]]$Values)
    $out = @()
    foreach ($v in @($Values)) { $s = ''; if ($null -ne $v) { $s = [string]$v }; $out += (($s -replace "[`r`n]+", ' ') -replace '\|', '/') }
    return ($out -join ' | ')
}
function Add-CcTableRow {
    param([Parameter(Mandatory=$true)][string]$File, [object[]]$Values)
    [IO.File]::AppendAllText($File, (ConvertTo-CcTableLine -Values $Values) + "`r`n")
}
# Format-CcTable FILE   -> pad every column to its widest value (in place).
function Format-CcTable {
    param([Parameter(Mandatory=$true)][string]$File)
    if (-not (Test-Path -LiteralPath $File)) { return }
    # An ArrayList keeps each row an array of its own, even with one row.
    $rows = New-Object System.Collections.ArrayList
    foreach ($line in @(Get-Content -LiteralPath $File)) { [void]$rows.Add(@($line -split '\|' | ForEach-Object { $_.Trim() })) }
    $w = @{}
    foreach ($r in $rows) { for ($i = 0; $i -lt $r.Count; $i++) { if (-not $w.ContainsKey($i) -or $r[$i].Length -gt $w[$i]) { $w[$i] = $r[$i].Length } } }
    $out = @()
    foreach ($r in $rows) {
        $cells = @(); for ($i = 0; $i -lt $r.Count; $i++) { $cells += $r[$i].PadRight($w[$i]) }
        $out += (($cells -join ' | ').TrimEnd())
    }
    [IO.File]::WriteAllText($File, (($out -join "`r`n") + "`r`n"))
}
# ConvertTo-CcTableFile CSV TXT   -> the CSV as a padded " | " table.
function ConvertTo-CcTableFile {
    param([string]$Csv, [string]$Txt)
    $first = @(Get-Content -LiteralPath $Csv -TotalCount 1)
    if ($first.Count -eq 0) { return }
    $cols = @($first[0] -split ',' | ForEach-Object { $_.Trim().Trim('"') })
    [IO.File]::WriteAllText($Txt, (ConvertTo-CcTableLine -Values $cols) + "`r`n")
    foreach ($row in @(Import-Csv -LiteralPath $Csv)) {
        $vals = @(); foreach ($col in $cols) { $vals += $row.$col }
        Add-CcTableRow -File $Txt -Values $vals
    }
    Format-CcTable -File $Txt
}

# -----------------------------------------------------------------------------
# Revert timer (the same as lib.sh's): never locked out
# -----------------------------------------------------------------------------
# Start-CcTimer -Seconds 120
#   After the changes, everything this run recorded with Add-CcUndo is undone
#   by itself unless the operator answers "keep" (Complete-CcTimer), having
#   logged in again from a NEW session.  The revert is a one-time scheduled
#   task running as SYSTEM, so it still happens if this RDP or PowerShell
#   session is cut off - which is the point.
#   Files in the run folder: undo.txt (this run's undo lines), revert.ps1
#   (runs them, newest first), revert.log, KEEP (made by "keep", or by hand
#   from another session: New-Item <run folder>\KEEP).
#   $env:BT_TEST_SCHTASKS = FILE: the schtasks command is written there, not run.
# Write-CcRevert   -> writes revert.ps1 in the run folder (it runs this run's
#   undo lines, newest first) and returns its path.  Start-CcTimer calls it;
#   a script with no timer calls it itself so its run can still be undone.
function Write-CcRevert {
    $c = $script:Cc
    if (-not $c.RunDir) { Stop-Cc -Code 1 -Message 'Write-CcRevert needs Use-CcNumberedDir first' }
    $revert = Join-Path $c.RunDir 'revert.ps1'
    $task = ('BT-revert-{0}-{1}' -f $c.Id, $c.Ts)
    $body = @'
# Undo one run of TASKID (made by the library's revert timer).
#   powershell -NoProfile -ExecutionPolicy Bypass -File revert.ps1 -Force
param([switch]$Force)
$d = Split-Path -Parent $MyInvocation.MyCommand.Path
$log = Join-Path $d 'revert.log'
if ((Test-Path -LiteralPath (Join-Path $d 'KEEP')) -and -not $Force) { exit 0 }
if (Test-Path -LiteralPath (Join-Path $d 'REVERTED')) { exit 0 }
[IO.File]::WriteAllText((Join-Path $d 'REVERTED'), [DateTime]::UtcNow.ToString('o'))
$lines = @()
if (Test-Path -LiteralPath (Join-Path $d 'undo.txt')) { $lines = @(Get-Content -LiteralPath (Join-Path $d 'undo.txt')) }
[Array]::Reverse($lines)
foreach ($l in $lines) {
    $cmd = ($l -split "`t")[3]
    if (-not $cmd) { continue }
    try { Invoke-Expression $cmd; [IO.File]::AppendAllText($log, ('ok: ' + $cmd + "`r`n")) }
    catch { [IO.File]::AppendAllText($log, ('FAILED: ' + $cmd + ' : ' + $_.Exception.Message + "`r`n")) }
}
if (Get-Command schtasks.exe -ErrorAction SilentlyContinue) { & schtasks.exe /Delete /TN 'TASKNAME' /F 2>&1 | Out-Null }
'@
    [IO.File]::WriteAllText($revert, $body.Replace('TASKID', $c.Id).Replace('TASKNAME', $task))
    if (-not (Test-Path -LiteralPath $c.RunUndo)) { [IO.File]::WriteAllText($c.RunUndo, '') }
    return $revert
}
function Start-CcTimer {
    param([int]$Seconds = 120)
    $c = $script:Cc
    if (-not $c.Apply) { return }
    if (-not $c.RunDir) { Stop-Cc -Code 1 -Message 'Start-CcTimer needs Use-CcNumberedDir first' }
    $revert = Write-CcRevert
    $task = ('BT-revert-{0}-{1}' -f $c.Id, $c.Ts)
    $at = [DateTime]::Now.AddSeconds($Seconds)
    # The task is made from an XML file: a /TR command with quotes inside
    # quotes is mangled by Windows PowerShell 5.1 on its way to schtasks.exe,
    # and the XML trigger keeps the exact time (no rounding to the minute).
    $arg = '-NoProfile -ExecutionPolicy Bypass -File "' + $revert + '"'
    $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Blue team revert timer: undo $($c.Id) $($c.Ts) unless it was kept</Description></RegistrationInfo>
  <Triggers><TimeTrigger><StartBoundary>$($at.ToString('yyyy-MM-ddTHH:mm:ss'))</StartBoundary><Enabled>true</Enabled></TimeTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><ExecutionTimeLimit>PT30M</ExecutionTimeLimit><Enabled>true</Enabled></Settings>
  <Actions Context="Author"><Exec><Command>powershell.exe</Command><Arguments>$([Security.SecurityElement]::Escape($arg))</Arguments></Exec></Actions>
</Task>
"@
    $xf = Join-Path $c.RunDir 'revert-task.xml'
    [IO.File]::WriteAllText($xf, $xml, [Text.Encoding]::Unicode)
    $args2 = @('/Create', '/TN', $task, '/XML', $xf, '/F')
    if ($env:BT_TEST_SCHTASKS) {
        [IO.File]::AppendAllText($env:BT_TEST_SCHTASKS, ('schtasks ' + ($args2 -join ' ') + '  # once at ' + $at.ToString('HH:mm:ss') + ', as SYSTEM' + "`r`n"))
    } else {
        $o = Invoke-CcProgram -FilePath schtasks.exe -Arguments $args2
        if ($LASTEXITCODE -ne 0) {
            Write-CcShow -Color Red -Text ('[x] The revert timer could not be set (schtasks: ' + (($o | Out-String).Trim()) + '). Undo by hand if needed: ' + $revert)
            return
        }
    }
    $c.TimerTask = $task; $c.TimerAt = $at
    Write-CcShow -Color Yellow -Text ('[*] Revert timer: everything is undone at {0} unless you keep it at the end.' -f $at.ToString('HH:mm:ss'))
}
# Stop-CcTimer   -> remove the scheduled revert (the changes stay).
function Stop-CcTimer {
    $c = $script:Cc
    if (-not $c.TimerTask) { return }
    if ($env:BT_TEST_SCHTASKS) { [IO.File]::AppendAllText($env:BT_TEST_SCHTASKS, ('schtasks /Delete /TN ' + $c.TimerTask + " /F`r`n")) }
    else { Invoke-CcProgram -FilePath schtasks.exe -Arguments @('/Delete', '/TN', $c.TimerTask, '/F') | Out-Null }
    $c.TimerTask = $null
}
# Complete-CcTimer   -> the keep question.  $true when the changes are kept.
#   -Batch keeps them; no console: they are undone unless KEEP is made.
function Complete-CcTimer {
    $c = $script:Cc
    if (-not $c.TimerTask) { return $true }
    $keep = Join-Path $c.RunDir 'KEEP'; $rev = Join-Path $c.RunDir 'REVERTED'; $revert = Join-Path $c.RunDir 'revert.ps1'
    Write-CcHeader 'KEEP OR REVERT'
    if (-not (Test-Path -LiteralPath $c.RunUndo) -or (Get-Item -LiteralPath $c.RunUndo).Length -eq 0) {
        Stop-CcTimer; [IO.File]::WriteAllText($keep, ''); return $true
    }
    if (Test-Path -LiteralPath $rev) { Write-CcShow -Color Red -Text ('[!] The revert timer already ran: the changes were undone (see ' + (Join-Path $c.RunDir 'revert.log') + ')'); return $false }
    if ($c.Batch) {
        [IO.File]::WriteAllText($keep, ''); Stop-CcTimer
        Write-CcShow -Color Green -Text ('[+] Changes kept (-Batch). Revert later: powershell -NoProfile -ExecutionPolicy Bypass -File "' + $revert + '" -Force')
        return $true
    }
    if (-not (Test-CcCanAsk)) {
        Write-CcShow -Color Yellow -Text ('[*] No console to ask. The changes are undone at {0} unless you run, from any session:  New-Item "{1}"' -f $c.TimerAt.ToString('HH:mm:ss'), $keep)
        return $true
    }
    Write-CcShow -Color Yellow -Text '[*] Check you can still get in: open a NEW RDP or PowerShell session and log in now.'
    if (Read-CcAsk -Question ('Keep these changes? (undone by themselves at ' + $c.TimerAt.ToString('HH:mm:ss') + ')') -Default N -Yes 'yes, keep them (I logged in from a new session)' -No 'no, put everything back now') {
        if (Test-Path -LiteralPath $rev) { Write-CcShow -Color Red -Text '[!] Too late: the timer ran out and the changes were undone'; return $false }
        [IO.File]::WriteAllText($keep, ''); Stop-CcTimer
        Write-CcShow -Color Green -Text ('[+] Changes kept. Revert later: powershell -NoProfile -ExecutionPolicy Bypass -File "' + $revert + '" -Force')
        return $true
    }
    Stop-CcTimer
    & $revert -Force | Out-Null
    Write-CcShow -Color Red -Text ('[!] Changes undone. What was done: ' + (Join-Path $c.RunDir 'revert.log'))
    return $false
}

# -----------------------------------------------------------------------------
# Start-up
# -----------------------------------------------------------------------------

# Initialize-Cc -Id 'WN-20' -Name 'short name' -Kind changes -Bound $PSBoundParameters
#   Call once at the top of every script.
#     -Kind   'readonly' for inventory/detection scripts, 'changes' for scripts
#             that can modify the system.  A 'changes' script refuses to run
#             with -Apply when there is no protected list (rule 4) unless the
#             operator passed -NoProtected.
#     -Bound  the script's $PSBoundParameters.  The library reads these keys
#             from it: Apply, Out, Protected, NoProtected, ForceScored, Quiet,
#             DebugLog.  Anything else in it is ignored.
#   Fills $Cc with Host, Ts, Out, Log, Undo, BackupDir, QuarDir, Kit, Protected.
function Initialize-Cc {
    param(
        [Parameter(Mandatory=$true)][string]$Id,
        [string]$Name = 'unnamed',
        [ValidateSet('readonly','changes')][string]$Kind = 'readonly',
        [System.Collections.IDictionary]$Bound = @{}
    )
    # Any unexpected error in start-up must stop the script, not let it carry
    # on half-configured.  (Local to this function; the caller is unaffected.)
    $ErrorActionPreference = 'Stop'
    $c = $script:Cc
    $c.Id = $Id; $c.Name = $Name; $c.Kind = $Kind
    foreach ($k in @('Apply','Quiet','DebugLog','ForceScored','NoProtected','Batch','NoColor')) {
        if ($Bound.ContainsKey($k)) { $c[$k] = [bool]$Bound[$k] }
    }

    # Tests answer the questions through $env:BT_TEST_ANSWERS ('y;n;;o').
    if ($null -ne $env:BT_TEST_ANSWERS) {
        $c.Answers = New-Object System.Collections.ArrayList
        foreach ($a in ($env:BT_TEST_ANSWERS -split ';')) { [void]$c.Answers.Add($a) }
        $c.AnswersUsed = $true
    }

    $h = $env:COMPUTERNAME
    if ([string]::IsNullOrEmpty($h)) { $h = [Environment]::MachineName }
    $c.Host = (($h -split '\.')[0]) -replace '[^A-Za-z0-9_-]', '_'
    $c.Ts = [DateTime]::UtcNow.ToString("yyyyMMdd'T'HHmmss'Z'")

    # Where the running script lives (the "kit").  Empty when the script was
    # pasted or piped into the session.
    $c.ScriptPath = $null; $c.Kit = $null
    try { $c.ScriptPath = $script:MyInvocation.MyCommand.Path } catch { }
    if ($c.ScriptPath) { $c.Kit = Split-Path -Parent $c.ScriptPath }

    # Output folder: operator-chosen, never inside the kit (rule 11).
    $out = $null
    if ($Bound.ContainsKey('Out') -and $Bound['Out']) { $out = [string]$Bound['Out'] }
    elseif ($env:BT_OUT) { $out = $env:BT_OUT }
    else { $out = Join-Path $HOME 'bt-out' }
    $out = Resolve-CcPath $out
    if ($c.Kit) {
        $kitFull = (Resolve-CcPath $c.Kit).TrimEnd('\','/')
        $sep = [IO.Path]::DirectorySeparatorChar
        if (($out + $sep).StartsWith($kitFull + $sep, [StringComparison]::OrdinalIgnoreCase)) {
            Stop-Cc -Code 2 -Message "output folder $out is inside the kit folder $kitFull; choose another with -Out"
        }
    }
    try {
        if (-not (Test-Path -LiteralPath $out)) { New-Item -ItemType Directory -Path $out -Force -ErrorAction Stop | Out-Null }
    } catch {
        Stop-Cc -Code 3 -Message "cannot create output folder: $out (pass -Out FOLDER). $($_.Exception.Message)"
    }
    $c.Out = $out
    $c.Log = Join-Path $out ('{0}_{1}_{2}.log' -f $c.Id, $c.Host, $c.Ts)
    $c.Undo = Join-Path $out ('undo-{0}.log' -f $c.Host)
    $c.BackupDir = Join-Path (Join-Path (Join-Path $out 'backup') $c.Host) ('{0}_{1}' -f $c.Ts, $c.Id)
    $c.QuarDir = Join-Path (Join-Path (Join-Path $out 'quarantine') $c.Host) ('{0}_{1}' -f $c.Ts, $c.Id)
    $c.Findings = $null
    try { [IO.File]::AppendAllText($c.Log, '') } catch { Stop-Cc -Code 3 -Message "cannot write log file: $($c.Log)" }

    # Protected list.
    $prot = $null
    if ($Bound.ContainsKey('Protected') -and $Bound['Protected']) { $prot = [string]$Bound['Protected'] }
    elseif ($env:BT_PROTECTED) { $prot = $env:BT_PROTECTED }
    else {
        # protected.txt; an old kit's protected.csv is still found.
        $prot = Join-Path $out 'protected.txt'
        $old = Join-Path $out 'protected.csv'
        if (-not (Test-Path -LiteralPath $prot) -and (Test-Path -LiteralPath $old)) { $prot = $old }
    }
    $c.ProtectedRows = $null
    if (Test-Path -LiteralPath $prot) {
        $c.Protected = Resolve-CcPath $prot
    } else {
        if ($Kind -eq 'changes' -and $c.Apply -and -not $c.NoProtected) {
            Stop-Cc -Code 3 -Message "no protected list at $prot - refusing to change anything. Build one (SH-09), pass -Protected FILE, or pass -NoProtected to accept the risk"
        }
        Write-CcLog -Level DEBUG -Message "no protected list at $prot (nothing will be refused)"
        $c.Protected = $null
    }

    $mode = 'DRY RUN (nothing will change)'
    if ($c.Apply) { $mode = 'APPLY (changes will be made)' }
    if ($c.Kind -eq 'readonly') { $mode = 'READ-ONLY (changes nothing on this host)' }
    Write-CcLog -Level INFO -Message ('start: {0} | lib {1} | host {2} | PowerShell {3} | {4}' -f $Name, $script:CcLibVersion, $c.Host, $PSVersionTable.PSVersion, $mode)
    Write-CcLog -Level DEBUG -Message ('out={0} log={1} protected={2} kit={3} kind={4}' -f $c.Out, $c.Log, $c.Protected, $c.Kit, $Kind)
    Test-CcSelf
}

# -----------------------------------------------------------------------------
# Making changes
# -----------------------------------------------------------------------------

# Add-CcUndo -Description 'what' -Command 'PowerShell that reverses it'
#   Append one line to this host's undo log.  Fields are tab-separated:
#       UTC time <TAB> script ID <TAB> description <TAB> command to undo
#   Newest entries are at the bottom; to roll back, run the commands from the
#   bottom up (SH-12 automates that).  Does nothing in a dry run.
function Add-CcUndo {
    param([string]$Description, [string]$Command)
    if (-not $script:Cc.Apply) { return }
    $line = "{0}`t{1}`t{2}`t{3}`r`n" -f ([DateTime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")), $script:Cc.Id, $Description, $Command
    [IO.File]::AppendAllText($script:Cc.Undo, $line)
    # This run's own copy: the revert timer and revert.ps1 undo just these.
    if ($script:Cc.RunUndo) { [IO.File]::AppendAllText($script:Cc.RunUndo, $line) }
}

# Invoke-CcProgram -FilePath netsh.exe -Arguments @('advfirewall','show','allprofiles')
#   Run an external program and return everything it printed (stdout and
#   stderr) as plain text lines.  $LASTEXITCODE holds its exit code afterwards.
#   Use this instead of calling programs directly inside Invoke-CcChange:
#   it switches error handling to 'Continue' for the call, so a program that
#   writes warnings to stderr is not mistaken for a failed step.  Success or
#   failure is then judged by the exit code alone.
function Invoke-CcProgram {
    param([Parameter(Mandatory=$true)][string]$FilePath, [string[]]$Arguments = @())
    $ErrorActionPreference = 'Continue'
    $lines = & $FilePath @Arguments 2>&1 | ForEach-Object { "$_" }
    return $lines
}

# Invoke-CcChange -Description 'text' -Action { ... } [-Undo 'command'] [-Secret]
#   The only way a script should change the system.  Returns $true or $false.
#     dry run: logs "WOULD: description" and returns $true
#     apply:   logs "DO: ...", runs the script block, writes its output to the
#              log file, counts success or failure
#   What counts as a failure: the block throws, a cmdlet in it errors (errors
#   are made terminating inside the block), or a program it ran left a
#   non-zero $LASTEXITCODE.
#   Running a program (reg.exe, netsh, sc.exe ...) inside the block: call it
#   through Invoke-CcProgram, and do not write '2>&1' or '2>$null' after it
#   yourself - see the note inside this function for why.
#   -Undo    recorded in the undo log only when the change succeeded.
#   -Secret  the block's output is NOT written to the log.  Use it whenever the
#            block handles a password.
#   The caller usually pipes the result to Out-Null, or tests it:
#       if (-not (Invoke-CcChange ...)) { continue }
function Invoke-CcChange {
    param(
        [Parameter(Mandatory=$true)][string]$Description,
        [Parameter(Mandatory=$true)][scriptblock]$Action,
        [string]$Undo,
        [switch]$Secret
    )
    $c = $script:Cc
    if (-not $c.Apply) {
        Write-CcLog -Level WOULD -Message $Description
        $c.Would++
        return $true
    }
    Write-CcLog -Level DO -Message $Description
    $ok = $true; $why = ''
    $global:LASTEXITCODE = 0
    try {
        # 'Stop' turns a cmdlet's ordinary (non-terminating) error into an
        # exception so it is counted as a failure.  The block's error stream is
        # deliberately NOT merged with 2>&1: on Windows PowerShell 2.0-5.1 that
        # combination makes any program that prints to stderr look like a
        # failure even when it succeeded.  Run programs with Invoke-CcProgram.
        $ErrorActionPreference = 'Stop'
        $output = & $Action
        if ($global:LASTEXITCODE -ne 0) { $ok = $false; $why = "program exit code $global:LASTEXITCODE" }
        if (-not $Secret -and $null -ne $output) {
            $text = ($output | Out-String).TrimEnd()
            if ($text) { try { [IO.File]::AppendAllText($c.Log, $text + "`r`n") } catch { } }
        }
    } catch {
        $ok = $false; $why = $_.Exception.Message
    }
    if ($ok) {
        $c.Done++
        if ($Undo) { Add-CcUndo -Description ('undo: ' + $Description) -Command $Undo }
    } else {
        $c.Failed++
        if ($Secret) { $why = 'details hidden because the step handles a secret' }
        Write-CcLog -Level ERROR -Message "FAILED: $Description - $why"
    }
    return $ok
}

# Backup-CcFile -Path C:\some\file
#   Copy a file or folder into this run's backup folder, keeping its full path
#   underneath (C:\inetpub\web.config -> <backup>\C\inetpub\web.config), and
#   record the restore command in the undo log.  Call it BEFORE changing the
#   file.  Returns the backup path, '' in a dry run or when there is nothing
#   to back up, and $null on failure - on $null the caller must NOT go on to
#   change the file.
function Backup-CcFile {
    param([Parameter(Mandatory=$true)][string]$Path)
    $c = $script:Cc
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-CcLog -Level DEBUG -Message "backup: $Path does not exist, nothing to save"
        return ''
    }
    $src = Resolve-CcPath $Path
    $rel = ($src -replace ':', '').TrimStart('\','/')
    $dst = Join-Path $c.BackupDir $rel
    if (-not $c.Apply) {
        Write-CcLog -Level WOULD -Message "back up $src"
        return ''
    }
    try {
        $parent = Split-Path -Parent $dst
        if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null }
        Copy-Item -LiteralPath $src -Destination $dst -Recurse -Force -ErrorAction Stop
        Add-CcUndo -Description "restore $src" -Command ('Copy-Item -LiteralPath {0} -Destination {1} -Recurse -Force' -f (ConvertTo-CcQuoted $dst), (ConvertTo-CcQuoted $src))
        Write-CcLog -Level DEBUG -Message "backup: $src -> $dst"
        return $dst
    } catch {
        Write-CcLog -Level ERROR -Message "backup FAILED for $src - do not change this file. $($_.Exception.Message)"
        return $null
    }
}

# Backup-CcRegistryKey -Key 'HKLM\SYSTEM\CurrentControlSet\Services\X'
#   Export a registry key (and everything under it) to a .reg file in the
#   backup folder with reg.exe, and record 'reg import' in the undo log.
#   Same return values as Backup-CcFile.  Key names use the reg.exe form
#   (HKLM\..., HKCU\...), not the PowerShell drive form (HKLM:\...).
function Backup-CcRegistryKey {
    param([Parameter(Mandatory=$true)][string]$Key)
    $c = $script:Cc
    $Key = $Key -replace '^(HK[A-Z]+):\\', '$1\'
    if (-not $c.Apply) {
        Write-CcLog -Level WOULD -Message "back up registry key $Key"
        return ''
    }
    if (-not (Test-CcWindows)) { return '' }
    try {
        if (-not (Test-Path -LiteralPath $c.BackupDir)) { New-Item -ItemType Directory -Path $c.BackupDir -Force -ErrorAction Stop | Out-Null }
        $file = Join-Path $c.BackupDir ((($Key -replace '[\\/:*?"<>| ]', '_')) + '.reg')
        Invoke-CcProgram -FilePath 'reg.exe' -Arguments @('export', $Key, $file, '/y') | Out-Null
        if ($LASTEXITCODE -ne 0) {
            # reg.exe fails when the key does not exist yet; that is not an error
            # for us, it just means there is nothing to restore.
            Write-CcLog -Level DEBUG -Message "registry backup: $Key not exported (it may not exist yet)"
            $global:LASTEXITCODE = 0
            return ''
        }
        Add-CcUndo -Description "restore registry key $Key" -Command ('reg.exe import {0}' -f (ConvertTo-CcQuoted $file))
        return $file
    } catch {
        Write-CcLog -Level ERROR -Message "registry backup FAILED for $Key - do not change this key. $($_.Exception.Message)"
        return $null
    }
}

# -----------------------------------------------------------------------------
# Protected list
# -----------------------------------------------------------------------------
# File format (protected.txt, parts split by spaces; old comma lines still
# work; see config/protected.example.txt):
#     type,value,note
#     port,80/tcp,scored web site
#     service,W3SVC,scored web site
#     account,svc-web,used by the scoring engine
#   type   one of: port service account path host process
#   value  compared without regard to case.  A port may be '80' (both
#          protocols) or '80/tcp'.  Asking about plain '80' matches '80/tcp'
#          too: when unsure, the answer is "protected".
#   Lines starting with # and blank lines are ignored.

# Test-CcProtected -Type port -Value '80/tcp'   -> $true if on the list.
function Test-CcProtected {
    param([Parameter(Mandatory=$true)][string]$Type, [Parameter(Mandatory=$true)][string]$Value)
    $c = $script:Cc
    if (-not $c.Protected) { return $false }
    if ($null -eq $c.ProtectedRows) {
        # Read once and keep.  Lines are cleaned by hand so a file saved by a
        # spreadsheet (quotes, stray spaces, comments) still parses.
        $rows = @()
        foreach ($line in @(Get-Content -LiteralPath $c.Protected)) {
            if ($null -eq $line) { continue }
            $t = $line.Trim()
            if ($t -eq '' -or $t.StartsWith('#')) { continue }
            # protected.txt is split by spaces; an old line (first word, then a comma) by commas.
            if ($t -match '^["\s]*[^\s,]+["\s]*,') { $parts = $t -split ',' } else { $parts = @($t -split '\s+') }
            if (@($parts).Count -lt 2) { continue }
            $ty = $parts[0].Trim().Trim('"').ToLower()
            $va = $parts[1].Trim().Trim('"').ToLower()
            if ($ty -eq 'type') { continue }
            $rows += ,@($ty, $va)
        }
        $c.ProtectedRows = $rows
        Write-CcLog -Level DEBUG -Message ('protected list: {0} entries loaded from {1}' -f @($rows).Count, $c.Protected)
    }
    $wantType = $Type.Trim().ToLower(); $wantVal = $Value.Trim().ToLower()
    foreach ($r in @($c.ProtectedRows)) {
        if ($r[0] -ne $wantType) { continue }
        if ($r[1] -eq $wantVal) { return $true }
        if ($wantType -eq 'port') {
            $a = ($r[1] -split '/')[0]; $b = ($wantVal -split '/')[0]
            if ($a -eq $b -and (-not $r[1].Contains('/') -or -not $wantVal.Contains('/'))) { return $true }
        }
    }
    return $false
}

# Test-CcAllowed -Type port -Value 80   -> $true if it is OK to change this.
#   Returns $false (and logs REFUSED) when the item is protected.  Typical use:
#       if (-not (Test-CcAllowed -Type service -Value $name)) { continue }
#   Accounts are the one type with an override: -ForceScored lets a script
#   touch a protected account, with a warning in the log (rule 5).
function Test-CcAllowed {
    param([Parameter(Mandatory=$true)][string]$Type, [Parameter(Mandatory=$true)][string]$Value)
    $c = $script:Cc
    if (Test-CcProtected -Type $Type -Value $Value) {
        if ($Type -eq 'account' -and $c.ForceScored) {
            Write-CcLog -Level WARN -Message "protected account '$Value' will be changed because -ForceScored was given"
            return $true
        }
        $c.Refused++
        Write-CcLog -Level REFUSED -Message "$Type '$Value' is on the protected list ($($c.Protected)) - skipped"
        return $false
    }
    return $true
}

# -----------------------------------------------------------------------------
# Hashing, passwords, quarantine
# -----------------------------------------------------------------------------

# Get-CcSha256 -Path file   -> lower-case hex SHA-256, or $null on failure.
#   Get-FileHash does not exist before PowerShell 4, so this uses .NET.  The
#   CryptoServiceProvider class is tried first because the "Managed" one
#   throws on Windows machines with the FIPS policy turned on.
function Get-CcSha256 {
    param([Parameter(Mandatory=$true)][string]$Path)
    $sha = $null; $fs = $null
    try {
        try { $sha = New-Object Security.Cryptography.SHA256CryptoServiceProvider } catch { $sha = [Security.Cryptography.SHA256]::Create() }
        $fs = [IO.File]::OpenRead((Resolve-CcPath $Path))
        $bytes = $sha.ComputeHash($fs)
        return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')
    } catch {
        Write-CcLog -Level DEBUG -Message "sha256 failed for $Path : $($_.Exception.Message)"
        return $null
    } finally {
        if ($fs) { $fs.Close() }
    }
}

# New-CcPassword [-Length 16]   -> one random password.
#   Characters: letters and digits without the look-alikes 0 O 1 l I, plus
#   '_' and '-'.  Always contains an upper-case letter, a lower-case letter
#   and a digit, and never starts with '-' or '_'.  Uses the system's
#   cryptographic random source, not Get-Random.
#   The password is RETURNED ONLY - this function never logs it.  Send it to
#   the operator's credential file, never to Write-CcLog, and run the step
#   that uses it through Invoke-CcChange -Secret.
function New-CcPassword {
    param([int]$Length = 16)
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789_-'
    $n = $chars.Length
    $limit = 256 - (256 % $n)      # reject bytes above this so every character is equally likely
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $buf = New-Object byte[] 1
    for ($try = 0; $try -lt 50; $try++) {
        $sb = New-Object Text.StringBuilder
        while ($sb.Length -lt $Length) {
            $rng.GetBytes($buf)
            if ($buf[0] -lt $limit) { [void]$sb.Append($chars[$buf[0] % $n]) }
        }
        $p = $sb.ToString()
        if ($p[0] -eq '-' -or $p[0] -eq '_') { continue }
        if ($p -cmatch '[A-Z]' -and $p -cmatch '[a-z]' -and $p -match '[0-9]') { return $p }
    }
    Write-CcLog -Level ERROR -Message 'New-CcPassword: could not generate a password'
    return $null
}

# Move-CcQuarantine -Path file
#   Move a suspicious file or folder out of the way without destroying it: it
#   goes to <out>\quarantine\<host>\<run>\<original path>, its SHA-256 is
#   logged, and the undo log gets the command that puts it back.  Refuses
#   paths on the protected list.  Returns $true on success or dry run.
function Move-CcQuarantine {
    param([Parameter(Mandatory=$true)][string]$Path)
    $c = $script:Cc
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-CcLog -Level DEBUG -Message "quarantine: $Path does not exist"
        return $true
    }
    $src = Resolve-CcPath $Path
    if (-not (Test-CcAllowed -Type path -Value $src)) { return $false }
    $rel = ($src -replace ':', '').TrimStart('\','/')
    $dst = Join-Path $c.QuarDir $rel
    $hash = 'n/a'
    if (-not (Test-Path -LiteralPath $src -PathType Container)) { $h = Get-CcSha256 -Path $src; if ($h) { $hash = $h } }
    if (-not $c.Apply) {
        Write-CcLog -Level WOULD -Message "quarantine $src (sha256 $hash)"
        $c.Would++
        return $true
    }
    try {
        $parent = Split-Path -Parent $dst
        if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force -ErrorAction Stop | Out-Null }
        Move-Item -LiteralPath $src -Destination $dst -Force -ErrorAction Stop
        $c.Done++
        Write-CcLog -Level DO -Message "quarantined $src -> $dst (sha256 $hash)"
        Add-CcUndo -Description "un-quarantine $src" -Command ('Move-Item -LiteralPath {0} -Destination {1} -Force' -f (ConvertTo-CcQuoted $dst), (ConvertTo-CcQuoted $src))
        return $true
    } catch {
        $c.Failed++
        Write-CcLog -Level ERROR -Message "quarantine FAILED for $src (file in use or access denied?). $($_.Exception.Message)"
        return $false
    }
}

# -----------------------------------------------------------------------------
# Output files
# -----------------------------------------------------------------------------

# ConvertTo-CcCsvLine @('a','b')   -> one CSV line: every field quoted, quotes
#   doubled, line breaks turned into spaces.
function ConvertTo-CcCsvLine {
    param([object[]]$Values)
    $out = @()
    foreach ($v in @($Values)) {
        $s = ''
        if ($null -ne $v) { $s = [string]$v }
        $s = ($s -replace "[`r`n]+", ' ') -replace '"', '""'
        $out += ('"' + $s + '"')
    }
    return ($out -join ',')
}

# New-CcCsv -Name ports -Header @('proto','port','process')
#   Creates a CSV with that header and returns its path.  Normally
#   <out>\<ID>_<host>_<time>_<Name>.csv; after Use-CcRunDir it is
#   <run folder>\<Name>.csv.
function New-CcCsv {
    param([Parameter(Mandatory=$true)][string]$Name, [Parameter(Mandatory=$true)][string[]]$Header)
    $c = $script:Cc
    if ($c.CsvDir) { $file = Join-Path $c.CsvDir ($Name + '.csv') }
    else { $file = Join-Path $c.Out ('{0}_{1}_{2}_{3}.csv' -f $c.Id, $c.Host, $c.Ts, $Name) }
    [IO.File]::WriteAllText($file, (($Header -join ',') + "`r`n"))
    return $file
}

# Add-CcCsvRow -File $f -Values @('tcp', 80, 'w3wp')   -> append one row.
#   Export-Csv -Append does not exist on PowerShell 2.0, hence this function.
function Add-CcCsvRow {
    param([Parameter(Mandatory=$true)][string]$File, [object[]]$Values)
    [IO.File]::AppendAllText($File, (ConvertTo-CcCsvLine -Values $Values) + "`r`n")
}

# Add-CcFinding -Weakness 'SMBv1 enabled' -FixId FIX-SMB1 -Class service -Detail '...' [-ProtectedDep 'port 445']
#   Detection scripts never fix anything; they write findings (the "detect,
#   then fix" rule).  A fix script later reads this file and acts by class:
#     safe       cannot break a scored service; applied in apply mode
#     service    might affect a service; skipped unless named explicitly
#     protected  would touch a protected item; always refused
#   File: <out>\<ID>_<host>_<time>_findings.csv with columns
#     host,script,weakness,fix_id,class,protected_dep,detail,time
function Add-CcFinding {
    param(
        [Parameter(Mandatory=$true)][string]$Weakness,
        [Parameter(Mandatory=$true)][string]$FixId,
        [Parameter(Mandatory=$true)][ValidateSet('safe','service','protected')][string]$Class,
        [string]$Detail = '',
        [string]$ProtectedDep = ''
    )
    $c = $script:Cc
    if (-not $c.Findings) {
        $c.Findings = New-CcCsv -Name findings -Header @('host','script','weakness','fix_id','class','protected_dep','detail','time')
    }
    Add-CcCsvRow -File $c.Findings -Values @($c.Host, $c.Id, $Weakness, $FixId, $Class, $ProtectedDep, $Detail, [DateTime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"))
    $c.FindingCount++
    Write-CcLog -Level FINDING -Message "[$Class] $Weakness ($FixId): $Detail"
}

# -----------------------------------------------------------------------------
# Inventory helpers: run folder, raw capture, flags
# -----------------------------------------------------------------------------
# Inventory scripts write many files.  They call Use-CcRunDir once after
# Initialize-Cc so everything for one run sits in one folder:
#     <out>\<ID>_<host>_<UTC time>\
#         <section>.csv        one per section       (New-CcCsv)
#         flags.csv            unusual items         (Add-CcFlag)
#         raw\<name>.txt       untouched tool output (Save-CcOutput)
# The log file and the undo log stay in <out> itself, beside every other
# script's, so all logs for a host are in one place.

# Use-CcRunDir   -> create the run folder and send CSV files there.
function Use-CcRunDir {
    $c = $script:Cc
    # Two runs in the same second would share one folder and mix their CSVs,
    # so add -2, -3, ... until the name is free.  The suffix still sorts after
    # the plain time, so "newest last" ordering keeps working.
    $base = '{0}_{1}_{2}' -f $c.Id, $c.Host, $c.Ts
    $c.RunDir = Join-Path $c.Out $base
    $n = 1
    while (Test-Path -LiteralPath $c.RunDir) {
        $n++
        if ($n -gt 99) { Stop-Cc -Code 3 -Message "too many run folders named $base-N in $($c.Out)" }
        $c.RunDir = Join-Path $c.Out ($base + '-' + $n)
    }
    try {
        New-Item -ItemType Directory -Path (Join-Path $c.RunDir 'raw') -Force -ErrorAction Stop | Out-Null
    } catch {
        Stop-Cc -Code 3 -Message "cannot create run folder $($c.RunDir): $($_.Exception.Message)"
    }
    $c.CsvDir = $c.RunDir
    Write-CcLog -Level DEBUG -Message ('run folder: ' + $c.RunDir)
}

# Save-CcOutput -Name netstat -Command { netstat -ano }
#   Run a READ-ONLY script block and keep its untouched output as text in
#   <run folder>\raw\<Name>.txt (or <out>\<ID>_<host>_<time>_<Name>.txt).
#   Errors from the block are written into the file instead of stopping the
#   script, because missing data is better than a stopped collector.
#   This does NOT honour dry-run: never pass it a block that changes things.
#   Returns the file path.
function Save-CcOutput {
    param([Parameter(Mandatory=$true)][string]$Name, [Parameter(Mandatory=$true)][scriptblock]$Command)
    $c = $script:Cc
    if ($c.RunDir) {
        $raw = Join-Path $c.RunDir 'raw'
        if (-not (Test-Path -LiteralPath $raw)) { New-Item -ItemType Directory -Path $raw -Force | Out-Null }
        $file = Join-Path $raw ($Name + '.txt')
    }
    else { $file = Join-Path $c.Out ('{0}_{1}_{2}_{3}.txt' -f $c.Id, $c.Host, $c.Ts, $Name) }
    $head = '# command: ' + $Command.ToString().Trim() + "`r`n# time: " + [DateTime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'") + "`r`n"
    $text = ''
    try {
        $ErrorActionPreference = 'Continue'
        $text = (& $Command 2>&1 | Out-String -Width 4096)
    } catch {
        $text = 'ERROR: ' + $_.Exception.Message
    }
    [IO.File]::WriteAllText($file, $head + $text)
    Write-CcLog -Level DEBUG -Message ('saved output to ' + $file)
    return $file
}

# Add-CcFlag -Severity HIGH -Section ports -Item '4444/tcp' -Detail 'nc.exe is listening'
#   Record something unusual that an operator should look at.  Inventory
#   scripts never act on what they see; a flag only says "look here".
#     HIGH  likely red team activity or an open door - look now
#     MED   risky or unusual - look soon
#     LOW   worth knowing - kept in the file, not shown on screen
#   Written to flags.csv (severity,section,item,detail,time) and to the log.
#   Not printed while the script runs; Show-CcFlagReport prints the HIGH and
#   MED ones at the end, worst first (rule 17).
#   Never put a password or other secret in -Item or -Detail.
function Add-CcFlag {
    param(
        [Parameter(Mandatory=$true)][ValidateSet('HIGH','MED','LOW')][string]$Severity,
        [Parameter(Mandatory=$true)][string]$Section,
        [string]$Item = '',
        [string]$Detail = ''
    )
    $c = $script:Cc
    if (-not $c.FlagsFile) {
        if ($c.CsvDir) { $c.FlagsFile = Join-Path $c.CsvDir 'flags.csv' }
        else { $c.FlagsFile = Join-Path $c.Out ('{0}_{1}_{2}_flags.csv' -f $c.Id, $c.Host, $c.Ts) }
        if (-not (Test-Path -LiteralPath $c.FlagsFile)) { [IO.File]::WriteAllText($c.FlagsFile, "severity,section,item,detail,time`r`n") }
    }
    Add-CcCsvRow -File $c.FlagsFile -Values @($Severity, $Section, $Item, $Detail, [DateTime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"))
    $c.FlagCount++
    Write-CcLog -Level NOTE -Message ('FLAG {0} [{1}] {2}: {3}' -f $Severity, $Section, $Item, $Detail)
}

# Limit-CcLine text   -> the text cut to 200 characters with '...' added.
#   Screen lines only; flags.csv keeps the full text.
function Limit-CcLine {
    param([string]$Text)
    if ($Text.Length -gt 200) { return $Text.Substring(0, 197) + '...' }
    return $Text
}

# Get-CcFlagReport [-Max 30]   -> the report as an array of text lines:
#   counts, the HIGH flags, then the MED flags, at most -Max lines in total,
#   then how many were cut and where flags.csv is.  LOW flags are counted but
#   never listed.  Show-CcFlagReport prints the same lines.
function Get-CcFlagReport {
    param([int]$Max = 30)
    $c = $script:Cc
    if (-not $c.FlagsFile -or -not (Test-Path -LiteralPath $c.FlagsFile)) { return @('Flags: none') }
    $rows = @(Import-Csv -LiteralPath $c.FlagsFile)
    $hi = @($rows | Where-Object { $_.severity -eq 'HIGH' })
    $me = @($rows | Where-Object { $_.severity -eq 'MED' })
    $lo = @($rows | Where-Object { $_.severity -eq 'LOW' })
    $out = @(('Flags: {0} high, {1} medium, {2} low' -f $hi.Count, $me.Count, $lo.Count))
    $shown = 0
    if ($hi.Count -gt 0) {
        $out += 'HIGH - look now'
        foreach ($r in $hi) { if ($shown -ge $Max) { break }; $out += (Limit-CcLine ('  [{0}] {1}: {2}' -f $r.section, $r.item, $r.detail)); $shown++ }
    }
    if ($me.Count -gt 0 -and $shown -lt $Max) {
        $out += 'MED - look soon'
        foreach ($r in $me) { if ($shown -ge $Max) { break }; $out += (Limit-CcLine ('  [{0}] {1}: {2}' -f $r.section, $r.item, $r.detail)); $shown++ }
    }
    $cut = $hi.Count + $me.Count - $shown
    if ($cut -gt 0) { $out += ('  ... {0} more high/medium not shown' -f $cut) }
    $ff = $c.FlagsFile
    if ($c.Numbered) { $ff = Join-Path $c.RunDir 'flags.txt' }   # the CSV becomes this table at the end
    if ($lo.Count + $cut -gt 0) { $out += ('All flags, including low: ' + $ff) }
    return $out
}

function Show-CcFlagReport {
    param([int]$Max = 30)
    foreach ($l in @(Get-CcFlagReport -Max $Max)) { Write-Host $l }
}

# -----------------------------------------------------------------------------
# Kit integrity and finish
# -----------------------------------------------------------------------------

# Test-CcSelf
#   Rule 15: the kit's hash is checked before each run.  tools/build.sh
#   writes SCRIPT.sha256 next to each script; when it is there (or
#   $env:BT_MANIFEST names a hash list), the running script's hash must match
#   it.  An older kit's MANIFEST.sha256 in the script's folder or one of the
#   two folders above is still read.  A mismatch stops the script with exit 3:
#   the file on this host is not the one you built.
#   $env:BT_SKIP_VERIFY = '1' turns the check off (for development).
function Test-CcSelf {
    $c = $script:Cc
    if ($env:BT_SKIP_VERIFY -eq '1') { Write-CcLog -Level DEBUG -Message 'verify: skipped (BT_SKIP_VERIFY=1)'; return }
    if (-not $c.ScriptPath) { Write-CcLog -Level DEBUG -Message 'verify: script was not started from a file, nothing to hash'; return }
    $man = $env:BT_MANIFEST
    if (-not $man -and (Test-Path -LiteralPath ($c.ScriptPath + '.sha256'))) { $man = $c.ScriptPath + '.sha256' }
    if (-not $man) {
        $d = $c.Kit
        for ($i = 0; $i -lt 3 -and $d; $i++) {
            $cand = Join-Path $d 'MANIFEST.sha256'
            if (Test-Path -LiteralPath $cand) { $man = $cand; break }
            $d = Split-Path -Parent $d
        }
    }
    if (-not $man -or -not (Test-Path -LiteralPath $man)) { Write-CcLog -Level DEBUG -Message 'verify: no MANIFEST.sha256 found (unbuilt copy), not checked'; return }
    $name = Split-Path -Leaf $c.ScriptPath
    $want = $null
    foreach ($line in @(Get-Content -LiteralPath $man)) {
        $parts = @($line -split '\s+', 2)
        if ($parts.Count -lt 2) { continue }
        $leaf = ($parts[1].Trim().TrimStart('*') -split '[\\/]')[-1]
        if ($leaf -eq $name) { $want = $parts[0].Trim().ToLower(); break }
    }
    if (-not $want) { Write-CcLog -Level WARN -Message "verify: $name is not listed in $man"; return }
    $got = Get-CcSha256 -Path $c.ScriptPath
    if (-not $got) { Write-CcLog -Level WARN -Message 'verify: could not hash the script, kit not checked'; return }
    if ($got -ne $want) {
        Stop-Cc -Code 3 -Message "KIT CHECK FAILED: $($c.ScriptPath) does not match $man. This copy was changed after it was built - do not run it. Re-copy the kit from the admin workstation"
    }
    Write-CcLog -Level DEBUG -Message "verify: $name matches the manifest"
}

# Complete-Cc [-ExitCode n]
#   Print the one-line summary and exit.  Without -ExitCode the code is 5 when
#   any change failed, otherwise 0.  Refusals are counted and shown but are not
#   a failure: a refusal is the protected list doing its job.
function Complete-Cc {
    param([int]$ExitCode = -1)
    $c = $script:Cc
    if ($ExitCode -lt 0) { if ($c.Failed -gt 0) { $ExitCode = 5 } else { $ExitCode = 0 } }
    Write-CcLog -Level INFO -Message ('done: changed={0} would-change={1} failed={2} refused={3} findings={4} exit={5}' -f $c.Done, $c.Would, $c.Failed, $c.Refused, $c.FindingCount, $ExitCode)
    if ($c.Would -gt 0) { Write-CcLog -Level INFO -Message ('this was a dry run - re-run with -Apply to make the {0} change(s)' -f $c.Would) }
    if ($c.Done -gt 0) { Write-CcLog -Level INFO -Message ('undo commands for this host are in {0}' -f $c.Undo) }
    if ($c.RunDir) { Write-CcLog -Level INFO -Message ('results: {0}' -f $c.RunDir) }
    if ($c.Log) { Write-CcLog -Level INFO -Message ('log: {0}' -f $c.Log) }
    # A numbered run folder keeps no CSV: each CSV working file becomes a .txt
    # table (unless the script wrote one) and the work folder goes.
    if ($c.Numbered -and $c.Work -and (Test-Path -LiteralPath $c.Work) -and $env:BT_TEST_KEEP_CSV -ne '1') {
        foreach ($f in @(Get-ChildItem -LiteralPath $c.Work -Filter '*.csv' -ErrorAction SilentlyContinue)) {
            $t = Join-Path $c.RunDir ([IO.Path]::GetFileNameWithoutExtension($f.Name) + '.txt')
            if (-not (Test-Path -LiteralPath $t)) { try { ConvertTo-CcTableFile -Csv $f.FullName -Txt $t } catch { } }
        }
        Remove-Item -LiteralPath $c.Work -Recurse -Force -ErrorAction SilentlyContinue
    }
    exit $ExitCode
}
# <<< BT-LIB

# ---- Options ----------------------------------------------------------------
function Split-List($a) { return @(@($a) | Where-Object { $_ } | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
$Services = Split-List $Services
$FixKinds = @('firewall', 'kill', 'enable', 'start', 'pool', 'recovery')
$Fix = @(Split-List $Fix | ForEach-Object { $_.ToLower() })
foreach ($k in $Fix) { if (-not ($FixKinds -contains $k)) { Write-Host ("unknown fix kind '{0}' ({1})" -f $k, ($FixKinds -join ' ')); exit 2 } }
if (-not (Test-CcBox $Box)) { Write-Host ("unknown box '{0}' (dc web ecomm fileshare db other)" -f $Box); exit 2 }
if ($Watch -lt 0 -or ($Watch -gt 0 -and $Watch -lt 5)) { Write-Host '-Watch must be 5 seconds or more'; exit 2 }
if ($AutoRestart -and $Watch -eq 0) { Write-Host '-AutoRestart needs -Watch SECONDS'; exit 2 }
function Lc($s) { if ($null -eq $s) { return '' }; return ([string]$s).ToLower() }
function Q([string]$s) { return ConvertTo-CcQuoted $s }

# ---- What each service needs ----------------------------------------------------
# name (wildcards allowed) -> ports, the program that should own them, web check, box kinds where it is scored
$Known = @(
    @{ N = 'W3SVC'; Ports = @(80); Owner = 'system'; Web = $true; Box = 'web ecomm'; What = 'IIS web server' },
    @{ N = 'WAS'; Ports = @(); Owner = ''; Web = $false; Box = 'web ecomm'; What = 'IIS process activation' },
    @{ N = 'Apache*'; Ports = @(80); Owner = 'httpd.exe'; Web = $true; Box = 'web ecomm'; What = 'Apache web server' },
    @{ N = 'nginx'; Ports = @(80); Owner = 'nginx.exe'; Web = $true; Box = 'web ecomm'; What = 'nginx web server' },
    @{ N = 'MSSQLSERVER'; Ports = @(1433); Owner = 'sqlservr.exe'; Web = $false; Box = 'db ecomm web'; What = 'SQL Server' },
    @{ N = 'MSSQL$*'; Ports = @(); Owner = 'sqlservr.exe'; Web = $false; Box = 'db ecomm web'; What = 'SQL Server (named)' },
    @{ N = 'MySQL*'; Ports = @(3306); Owner = 'mysqld.exe'; Web = $false; Box = 'db ecomm web'; What = 'MySQL' },
    @{ N = 'MariaDB*'; Ports = @(3306); Owner = 'mysqld.exe'; Web = $false; Box = 'db ecomm web'; What = 'MariaDB' },
    @{ N = 'NTDS'; Ports = @(389, 3268); Owner = 'lsass.exe'; Web = $false; Box = 'dc'; What = 'Active Directory' },
    @{ N = 'Kdc'; Ports = @(88); Owner = 'lsass.exe'; Web = $false; Box = 'dc'; What = 'Kerberos' },
    @{ N = 'DNS'; Ports = @(53); Owner = 'dns.exe'; Web = $false; Box = 'dc'; What = 'DNS server' },
    @{ N = 'Netlogon'; Ports = @(); Owner = ''; Web = $false; Box = 'dc'; What = 'domain logons' },
    @{ N = 'W32Time'; Ports = @(); Owner = ''; Web = $false; Box = 'dc'; What = 'time (Kerberos needs it)' },
    @{ N = 'ADWS'; Ports = @(9389); Owner = 'microsoft.activedirectory.webservices.exe'; Web = $false; Box = 'dc'; What = 'AD web services' },
    @{ N = 'DFSR'; Ports = @(); Owner = ''; Web = $false; Box = 'dc'; What = 'SYSVOL replication' },
    @{ N = 'LanmanServer'; Ports = @(445); Owner = 'system'; Web = $false; Box = 'dc fileshare'; What = 'file sharing (SMB)' },
    @{ N = 'TermService'; Ports = @(3389); Owner = 'svchost.exe'; Web = $false; Box = 'all'; What = 'Remote Desktop' },
    @{ N = 'WinRM'; Ports = @(5985); Owner = 'system'; Web = $false; Box = ''; What = 'remote PowerShell' },
    @{ N = 'FTPSVC'; Ports = @(21); Owner = 'svchost.exe'; Web = $false; Box = ''; What = 'IIS FTP' },
    @{ N = 'EventLog'; Ports = @(); Owner = ''; Web = $false; Box = 'all'; What = 'the event log (red team stops it to hide)' }
)
function Get-Known([string]$name) { foreach ($k in $Known) { if ($name -like $k.N) { return $k } }; return $null }

# ---- Start ------------------------------------------------------------------
Initialize-Cc -Id 'WN-50' -Name 'Windows service recovery' -Kind changes -Bound $PSBoundParameters
$Fake = $env:BT_WN50_FAKE
if ($Fake) { Write-CcLog -Level WARN -Message "TEST MODE: stand-in state from $Fake; nothing real is read or changed" }
Use-CcNumberedDir 'recovery'
Write-CcShow -Color Cyan -Text ('WN-50 Windows service recovery | host {0} | results in {1}' -f $Cc.Host, $Cc.RunDir)
Write-CcLegend -Marks @('Green=[ok] up', 'Red=[!] down or broken', 'Yellow=[*] a problem', 'Yellow=[~] would fix', 'Green=[+] fixed', 'Red=[x] failed')
if ($Cc.Apply -and -not $Fake) { Assert-CcAdmin }

# ---- Reading (or the stand-in) ------------------------------------------------------
function FP([string]$n) { return (Join-Path $Fake $n) }
function F-Read([string]$n) { $p = FP $n; if (-not (Test-Path -LiteralPath $p)) { return @() }; return @(Import-Csv -LiteralPath $p) }
function R-Services {
    if ($Fake) { return @(F-Read 'services.csv' | ForEach-Object { New-Object PSObject -Property @{ Name = $_.name; Display = $_.display; State = $_.state; Mode = $_.startmode; Path = $_.path } }) }
    $s = @(Get-WmiObject -Class Win32_Service -ErrorAction SilentlyContinue)
    return @($s | ForEach-Object { New-Object PSObject -Property @{ Name = [string]$_.Name; Display = [string]$_.DisplayName; State = [string]$_.State; Mode = [string]$_.StartMode; Path = [string]$_.PathName } })
}
function R-Listeners {
    $lines = @(); $procs = @{}
    if ($Fake) {
        $p = FP 'netstat.txt'; if (Test-Path -LiteralPath $p) { $lines = @([IO.File]::ReadAllLines($p)) }
        foreach ($r in @(F-Read 'processes.csv')) { $procs[$r.pid] = $r }
    } else {
        $lines = @(Invoke-CcProgram -FilePath 'netstat.exe' -Arguments @('-ano'))
        foreach ($p in @(Get-WmiObject -Class Win32_Process -ErrorAction SilentlyContinue)) { $procs[[string]$p.ProcessId] = New-Object PSObject -Property @{ pid = [string]$p.ProcessId; name = [string]$p.Name; path = [string]$p.ExecutablePath } }
    }
    $out = @{}
    foreach ($l in $lines) {
        $f = @($l.Trim() -split '\s+')
        if ($f.Count -lt 5 -or $f[0].ToUpper() -ne 'TCP') { continue }
        $ri = $f[2].LastIndexOf(':'); if ($ri -lt 0 -or $f[2].Substring($ri + 1) -ne '0') { continue }
        $li = $f[1].LastIndexOf(':'); if ($li -lt 0) { continue }
        $port = 0; if (-not [int]::TryParse($f[1].Substring($li + 1), [ref]$port)) { continue }
        if ($out.ContainsKey($port)) { continue }
        $procId = $f[4]; $pr = $procs[$procId]; $name = ''; $path = ''
        if ($pr) { $name = [string]$pr.name; $path = [string]$pr.path }; if ($procId -eq '4') { $name = 'System' }
        $out[$port] = New-Object PSObject -Property @{ Pid = $procId; Name = $name; Path = $path }
    }
    return $out
}
# Inbound block rules: name, ports text, protocol.
function R-BlockRules {
    if ($Fake) { return @(F-Read 'fwrules.csv' | Where-Object { $_.enabled -eq 'True' -and $_.action -eq 'Block' -and $_.dir -eq 'In' } | ForEach-Object { New-Object PSObject -Property @{ Name = $_.name; Ports = $_.ports; Proto = $_.protocol } }) }
    $out = @()
    try {
        $fw = New-Object -ComObject HNetCfg.FwPolicy2
        foreach ($r in @($fw.Rules)) {
            if (-not $r.Enabled -or $r.Direction -ne 1 -or $r.Action -ne 0) { continue }
            if ($r.Protocol -ne 6 -and $r.Protocol -ne 256) { continue }
            $out += New-Object PSObject -Property @{ Name = [string]$r.Name; Ports = [string]$r.LocalPorts; Proto = $(if ($r.Protocol -eq 6) { 'TCP' } else { 'Any' }) }
        }
    } catch { Write-CcLog -Level WARN -Message ('firewall rules not read: ' + $_.Exception.Message) }
    return $out
}
function Test-PortIn([string]$spec, [int]$port) {
    if (-not $spec -or $spec -eq '*' -or (Lc $spec) -eq 'any') { return $true }
    foreach ($p in ($spec -split ',')) {
        $p = $p.Trim()
        if ($p -match '^(\d+)-(\d+)$') { if ($port -ge [int]$matches[1] -and $port -le [int]$matches[2]) { return $true } }
        elseif ($p -eq [string]$port) { return $true }
    }
    return $false
}
$AppCmd = ''; if ($env:windir) { $AppCmd = Join-Path $env:windir 'System32\inetsrv\appcmd.exe' }
function R-Iis {
    if ($Fake) { return @(F-Read 'iis.csv' | ForEach-Object { New-Object PSObject -Property @{ Kind = $_.kind; Name = $_.name; State = $_.state } }) }
    $out = @()
    if (-not $AppCmd -or -not (Test-Path -LiteralPath $AppCmd)) { return $out }
    foreach ($k in @('site', 'apppool')) {
        foreach ($l in @(Invoke-CcProgram -FilePath $AppCmd -Arguments @('list', $k))) {
            # SITE "Default Web Site" (id:1,bindings:...,state:Started)   APPPOOL "DefaultAppPool" (MgdVersion:v4.0,MgdMode:Integrated,state:Started)
            if ($l -match '^\w+\s+"([^"]+)"\s+\(.*state:(\w+)') { $out += New-Object PSObject -Property @{ Kind = $k; Name = $matches[1]; State = $matches[2] } }
        }
    }
    return $out
}
function R-Recovery([string]$name) {
    if ($Fake) { foreach ($r in @(F-Read 'services.csv')) { if ($r.name -eq $name) { return ($r.recovery -eq 'restart') } }; return $false }
    $t = (@(Invoke-CcProgram -FilePath 'sc.exe' -Arguments @('qfailure', $name)) -join ' ')
    return ($t -match 'RESTART')
}
function R-DiskFree {
    if ($Fake) { $p = FP 'disk.txt'; if (Test-Path -LiteralPath $p) { return [int]([IO.File]::ReadAllText($p).Trim()) }; return 50 }
    try {
        $d = Get-WmiObject -Class Win32_LogicalDisk -Filter ("DeviceID='" + $env:SystemDrive + "'") -ErrorAction Stop
        if ($d.Size -gt 0) { return [int](100 * $d.FreeSpace / $d.Size) }
    } catch { }
    return 100
}
# Test-Answers PORT WEB -> '' when it answers, or why not.
function Test-Answers([int]$port, [bool]$web) {
    if ($Fake) {
        $l = R-Listeners; if (-not $l.ContainsKey($port)) { return 'nothing answers' }
        if ($web) { $p = FP 'http-status.txt'; if (Test-Path -LiteralPath $p) { $c = [int]([IO.File]::ReadAllText($p).Trim()); if ($c -ge 500) { return ('the page answers ' + $c) } } }
        return ''
    }
    if ($web) {
        try {
            $req = [Net.HttpWebRequest]::Create('http://127.0.0.1:' + $port + '/'); $req.Timeout = 8000; $req.AllowAutoRedirect = $false
            $resp = $req.GetResponse(); $resp.Close(); return ''
        } catch [Net.WebException] {
            if ($_.Exception.Response) { $c = [int]$_.Exception.Response.StatusCode; if ($c -ge 500) { return ('the page answers ' + $c) }; return '' }
            return ('no answer: ' + $_.Exception.Message)
        } catch { return 'no answer' }
    }
    try {
        $tc = New-Object Net.Sockets.TcpClient; $ar = $tc.BeginConnect('127.0.0.1', $port, $null, $null)
        $ok = $ar.AsyncWaitHandle.WaitOne(3000, $false); if ($ok) { $tc.EndConnect($ar) }; $tc.Close()
        if ($ok) { return '' } else { return 'no answer in 3 seconds' }
    } catch { return 'connection refused' }
}
$OddRe = '(\\users\\public\\|\\perflogs\\|\\windows\\temp\\|\\temp\\|\\tmp\\|\\appdata\\|\\downloads\\|\$recycle\.bin)'
function Get-Exe([string]$cmd) {
    $c = $cmd.Trim(); if (-not $c) { return '' }
    if ($c.StartsWith('"')) { $e = $c.IndexOf('"', 1); if ($e -gt 0) { return $c.Substring(1, $e - 1) } }
    $m = [regex]::Match($c, '^(.+?\.exe)', 'IgnoreCase'); if ($m.Success) { return $m.Groups[1].Value }
    return ($c -split '\s+')[0]
}

# ---- 1/4 Questions and what to check -------------------------------------------------
Write-CcHeader '1/4  questions and what to check'
if (-not $Box) { $Box = Read-CcBox -Question 'Which box is this? (its scored services come first)' }
$script:all = @(R-Services); $all = $script:all
$byName = @{}; foreach ($s in $all) { $byName[(Lc $s.Name)] = $s }
$check = New-Object System.Collections.ArrayList
function Add-Check($s, [string]$why) { foreach ($c in $check) { if ($c.Svc.Name -eq $s.Name) { return } }; [void]$check.Add((New-Object PSObject -Property @{ Svc = $s; K = (Get-Known $s.Name); Why = $why; Problems = @(); Fixes = @(); Result = ''; Unused = $false; Applied = '' })) }
if ($Services.Count -gt 0) {
    foreach ($n in $Services) {
        $m = @($all | Where-Object { $_.Name -like $n })
        if ($m.Count -eq 0) { Write-CcShow -Color Yellow -Text ('  [*] {0}: no such service on this box' -f $n) }
        foreach ($s in $m) { Add-Check $s '-Services' }
    }
} else {
    $prot = @(); if ($Cc.Protected) { foreach ($s in $all) { if (Test-CcProtected -Type service -Value $s.Name) { $prot += $s } } }
    foreach ($s in $prot) { Add-Check $s 'protected list (scored)' }
    foreach ($k in $Known) { foreach ($s in @($all | Where-Object { $_.Name -like $k.N })) { if ($k.Box -eq 'all' -or ($k.Box -split ' ') -contains $Box -or $s.State -eq 'Running' -or $s.Mode -eq 'Auto') { Add-Check $s $k.What } } }
    $scored = @($check | Where-Object { $_.Why -eq 'protected list (scored)' -or ($_.K -and (($_.K.Box -split ' ') -contains $Box)) })
    if ($check.Count -gt $scored.Count -and $scored.Count -gt 0) {
        $names = ($check | ForEach-Object { $_.Svc.Name }) -join ' '
        $a = Read-CcChoice -Question ('Check which services? (found: ' + $names + ')') -Default a -Options @('a=all of them', ('s=only the scored ones for a ' + $Box + ' box (' + (($scored | ForEach-Object { $_.Svc.Name }) -join ' ') + ')'))
        if ($a -eq 's') { $keep = @($scored); $check.Clear(); foreach ($c in $keep) { [void]$check.Add($c) } }
    }
    if ($Box -eq 'dc') { foreach ($k in $Known) { if (($k.Box -split ' ') -contains 'dc' -and $k.N -notmatch '\*' -and -not $byName.ContainsKey((Lc $k.N)) -and $k.N -ne 'FTPSVC') { Write-CcShow -Color Yellow -Text ('  [*] {0} ({1}) is not installed on this domain controller' -f $k.N, $k.What) } } }
}
if ($check.Count -eq 0) { Write-CcShow -Color Yellow -Text '  [*] nothing to check: name services with -Services' }

# ---- The fixes -------------------------------------------------------------------------
# Each fix: Kind, Text, Default (y/n), Do (a command string), Undo (a command string).
function F-SetCmd([string]$file, [string]$keyCol, [string]$key, [string]$col, [string]$val) {
    return ('$f = ' + (Q (FP $file)) + '; $r = @(Import-Csv -LiteralPath $f); foreach ($x in $r) { if ($x.' + $keyCol + ' -eq ' + (Q $key) + ') { $x.' + $col + ' = ' + (Q $val) + ' } }; $r | Export-Csv -LiteralPath $f -NoTypeInformation')
}
function New-Fix($c, [string]$kind, [string]$text, [string]$def, [string]$do, [string]$undo) {
    $c.Fixes += New-Object PSObject -Property @{ Kind = $kind; Text = $text; Default = $def; Do = $do; Undo = $undo; Chosen = $false; Done = '' }
}
function Start-Cmd($s, $k) {
    if ($Fake) {
        $cmd = F-SetCmd 'services.csv' 'name' $s.Name 'state' 'Running'
        if ($k) { foreach ($p in $k.Ports) {
            $pid2 = '7' + $p; $own = $k.Owner; if ($own -eq 'system') { $pid2 = '4' }
            $cmd += ('; Add-Content -LiteralPath ' + (Q (FP 'netstat.txt')) + ' -Value ' + (Q ('  TCP    0.0.0.0:' + $p + '    0.0.0.0:0    LISTENING    ' + $pid2)))
            if ($pid2 -ne '4') { $cmd += ('; Add-Content -LiteralPath ' + (Q (FP 'processes.csv')) + ' -Value ' + (Q ($pid2 + ',' + $own + ',C:\Program Files\x\' + $own))) }
        } }
        return $cmd
    }
    return ('Start-Service -Name ' + (Q $s.Name) + ' -ErrorAction Stop')
}
function Stop-Cmd($s) { if ($Fake) { return (F-SetCmd 'services.csv' 'name' $s.Name 'state' 'Stopped') }; return ('Stop-Service -Name ' + (Q $s.Name) + ' -Force') }

# ---- 2/4 Checks --------------------------------------------------------------------------
function Check-One($c, [bool]$quiet) {
    $s = $c.Svc; $k = $c.K; $c.Problems = @(); $c.Fixes = @(); $c.Unused = $false
    $listen = R-Listeners
    $exe = Get-Exe $s.Path
    if ($exe -and -not $Fake -and -not (Test-Path -LiteralPath $exe)) { $c.Problems += ('its program is missing: ' + $exe + ' (reinstall the role or feature, or restore it from the WN-35 backup)') }
    if ($exe -and (Lc $exe) -match $OddRe) { $c.Problems += ('its program is in a temp or user folder: ' + $exe + ' - red team may have replaced it (WN-42)') }
    $running = ($s.State -eq 'Running')
    # Firewall first: a block rule on its port.
    $rules = @(R-BlockRules)
    if ($k) { foreach ($p in $k.Ports) { foreach ($r in $rules) { if (Test-PortIn $r.Ports $p) {
        $c.Problems += ('the firewall blocks port {0}: rule "{1}"' -f $p, $r.Name)
        $do = $(if ($Fake) { F-SetCmd 'fwrules.csv' 'name' $r.Name 'enabled' 'False' } else { 'netsh.exe advfirewall firewall set rule name=' + (Q $r.Name) + ' new enable=no' })
        $un = $(if ($Fake) { F-SetCmd 'fwrules.csv' 'name' $r.Name 'enabled' 'True' } else { 'netsh.exe advfirewall firewall set rule name=' + (Q $r.Name) + ' new enable=yes' })
        New-Fix $c 'firewall' ('turn off the firewall rule "' + $r.Name + '" (it blocks port ' + $p + ')') 'y' $do $un
    } } } }
    # Another program on its port.  When it is another known server that is
    # running (Apache from XAMPP on 80 while IIS is stopped), this one is not
    # in use: reported, nothing offered.
    if ($k -and $k.Owner) { foreach ($p in $k.Ports) {
        if (-not $listen.ContainsKey($p)) { continue }
        $o = $listen[$p]; $on = Lc $o.Name
        if ($on -eq $k.Owner) { continue }
        $other = ''
        foreach ($kk in $Known) { if ($kk.Owner -eq $on -and $kk.N -ne $k.N) { foreach ($s2 in $script:all) { if ($s2.Name -like $kk.N -and $s2.State -eq 'Running') { $other = $s2.Name } } } }
        if ($other -and -not $running) { $c.Problems += ('port {0} is served by {1} ({2}): {3} is not the one in use here' -f $p, $other, $o.Name, $s.Name); $c.Unused = $true; continue }
        $odd = ((Lc $o.Path) -match $OddRe)
        $c.Problems += ('another program holds port {0}: {1} (pid {2}{3})' -f $p, $o.Name, $o.Pid, $(if ($o.Path) { ', ' + $o.Path } else { '' }))
        $do = $(if ($Fake) { '$f = ' + (Q (FP 'netstat.txt')) + '; [IO.File]::WriteAllLines($f, [string[]]@([IO.File]::ReadAllLines($f) | Where-Object { ($_.Trim() -split ''\s+'')[-1] -ne ' + (Q $o.Pid) + ' }))' } else { 'Stop-Process -Id ' + $o.Pid + ' -Force -ErrorAction Stop' })
        New-Fix $c 'kill' ('stop ' + $o.Name + ' (pid ' + $o.Pid + ') so ' + $s.Name + ' gets port ' + $p) $(if ($odd -or -not $o.Name) { 'y' } else { 'n' }) $do ('Write-Host ' + (Q ('WN-50 stopped ' + $o.Name + ' (pid ' + $o.Pid + '): start it again by hand if it was needed')))
    } }
    if ($c.Unused) { $c.Result = 'not in use: ' + ($c.Problems -join '; '); return }
    if ($s.Mode -eq 'Disabled') {
        $c.Problems += 'disabled: it cannot start'
        $old = @{ Auto = 'auto'; Manual = 'demand'; Disabled = 'disabled' }[$s.Mode]
        $do = $(if ($Fake) { F-SetCmd 'services.csv' 'name' $s.Name 'startmode' 'Auto' } else { 'sc.exe config ' + (Q $s.Name) + ' start= auto' })
        $un = $(if ($Fake) { F-SetCmd 'services.csv' 'name' $s.Name 'startmode' $s.Mode } else { 'sc.exe config ' + (Q $s.Name) + ' start= ' + $old })
        New-Fix $c 'enable' ('set ' + $s.Name + ' to start at boot (Automatic)') 'y' $do $un
    }
    if (-not $running) {
        $c.Problems += ('not running (' + $s.State + ')')
        New-Fix $c 'start' ('start ' + $s.Name) 'y' (Start-Cmd $s $k) (Stop-Cmd $s)
    } else {
        $deaf = @()
        if ($k) { foreach ($p in $k.Ports) { if (-not $listen.ContainsKey($p)) { $deaf += $p } } }
        foreach ($p in $deaf) { $c.Problems += ('running, but nothing listens on port ' + $p) }
        if ($k) { foreach ($p in $k.Ports) { if ($listen.ContainsKey($p)) { $why = Test-Answers $p $k.Web; if ($why) { $c.Problems += ('port ' + $p + ': ' + $why) ; $deaf += $p } } } }
        if ($deaf.Count -gt 0 -and @($c.Fixes | Where-Object { $_.Kind -eq 'kill' -or $_.Kind -eq 'firewall' }).Count -eq 0) {
            $do = $(if ($Fake) { (Stop-Cmd $s) + '; ' + (Start-Cmd $s $k) } else { 'Restart-Service -Name ' + (Q $s.Name) + ' -Force -ErrorAction Stop' })
            New-Fix $c 'start' ('restart ' + $s.Name) 'y' $do ('Write-Host ' + (Q ('WN-50 restarted ' + $s.Name + ': nothing to undo')))
        }
    }
    # IIS: stopped sites and app pools.
    if ($s.Name -eq 'W3SVC') {
        foreach ($i in @(R-Iis)) {
            if ($i.State -eq 'Started') { continue }
            $c.Problems += ('IIS {0} "{1}" is {2}' -f $i.Kind, $i.Name, $i.State)
            $arg = $(if ($i.Kind -eq 'site') { '/site.name:' } else { '/apppool.name:' })
            $do = $(if ($Fake) { F-SetCmd 'iis.csv' 'name' $i.Name 'state' 'Started' } else { '& ' + (Q $AppCmd) + ' start ' + $i.Kind + ' ' + (Q ($arg + $i.Name)) })
            $un = $(if ($Fake) { F-SetCmd 'iis.csv' 'name' $i.Name 'state' $i.State } else { '& ' + (Q $AppCmd) + ' stop ' + $i.Kind + ' ' + (Q ($arg + $i.Name)) })
            New-Fix $c 'pool' ('start the IIS ' + $i.Kind + ' "' + $i.Name + '"') 'y' $do $un
        }
    }
    # Restart on crash: for the scored ones that are not set to.
    if ($k -and $k.N -ne 'EventLog' -and -not (R-Recovery $s.Name)) {
        $do = $(if ($Fake) { F-SetCmd 'services.csv' 'name' $s.Name 'recovery' 'restart' } else { 'sc.exe failure ' + (Q $s.Name) + ' reset= 86400 actions= restart/5000/restart/10000/restart/30000' })
        $un = $(if ($Fake) { F-SetCmd 'services.csv' 'name' $s.Name 'recovery' '' } else { 'cmd.exe /c ' + (Q ('sc.exe failure "' + $s.Name + '" reset= 0 actions= ""')) })
        New-Fix $c 'recovery' ('make ' + $s.Name + ' restart by itself when it crashes (after 5 s, 10 s, 30 s)') 'y' $do $un
    }
    $c.Result = $(if (@($c.Problems).Count -eq 0) { 'up' } else { ($c.Problems -join '; ') })
}
function Show-One($c) {
    $s = $c.Svc
    if ($c.Unused) { Write-CcShow -Color DarkGray -Text ('  [-] {0,-14} {1}, {2}: {3}' -f $s.Name, $s.State, $s.Mode, ($c.Problems -join '; ')); return }
    $ports = ''; if ($c.K -and $c.K.Ports.Count -gt 0) { $ports = ' port ' + ($c.K.Ports -join ',') }
    if (@($c.Problems).Count -eq 0) { Write-CcShow -Color Green -Text ('  [ok] {0,-14} running{1} ({2})' -f $s.Name, $ports, $c.Why); return }
    $down = ($s.State -ne 'Running' -or @($c.Problems | Where-Object { $_ -like 'running, but*' -or $_ -like 'port *' }).Count -gt 0)
    Write-CcShow -Color $(if ($down) { 'Red' } else { 'Yellow' }) -Text ('  {0} {1,-14} {2}, {3}{4} ({5})' -f $(if ($down) { '[!]' } else { '[*]' }), $s.Name, $s.State, $s.Mode, $ports, $c.Why)
    foreach ($p in $c.Problems) { Write-CcShow -Color DarkGray -Text ('        - ' + $p) }
}

# ---- Watch mode -------------------------------------------------------------------------
if ($Watch -gt 0) {
    Write-CcHeader ('2/2  watching every {0} s (Ctrl-C to stop)' -f $Watch)
    $wf = Join-Path $Cc.RunDir 'watch.txt'
    $last = @{}; $tries = @{}; $gaveUp = @{}; $round = 0
    while ($true) {
        $round++
        $now = @(R-Services); $map = @{}; foreach ($s in $now) { $map[(Lc $s.Name)] = $s }
        $listen = R-Listeners
        foreach ($c in $check) {
            $s = $map[(Lc $c.Svc.Name)]; if (-not $s) { continue }
            $st = 'up'; $why = ''
            if ($s.State -ne 'Running') { $st = 'down'; $why = $s.State }
            elseif ($c.K) { foreach ($p in $c.K.Ports) { if (-not $listen.ContainsKey($p)) { $st = 'down'; $why = 'nothing on port ' + $p } } }
            $key = Lc $s.Name
            if (-not $last.ContainsKey($key) -or $last[$key] -ne $st) {
                $line = ('{0}  {1,-14} {2}{3}' -f [DateTime]::Now.ToString('HH:mm:ss'), $s.Name, $(if ($st -eq 'up') { 'UP' } else { 'DOWN' }), $(if ($why) { ' (' + $why + ')' } else { '' }))
                if ($last.ContainsKey($key) -or $st -eq 'down') { Write-CcShow -Color $(if ($st -eq 'up') { 'Green' } else { 'Red' }) -Text ('  ' + $line); [IO.File]::AppendAllText($wf, $line + "`r`n") }
                $last[$key] = $st
            }
            if ($st -eq 'down' -and $s.State -ne 'Running' -and $AutoRestart -and $Cc.Apply -and $s.Mode -ne 'Disabled') {
                $t = @(); if ($tries.ContainsKey($key)) { $t = @($tries[$key] | Where-Object { $_ -gt [DateTime]::Now.AddMinutes(-10) }) }
                if ($t.Count -ge 3) { if (-not $gaveUp.ContainsKey($key)) { Write-CcShow -Color Red -Text ('  [!] {0} went down 3 times in 10 minutes: not starting it again - find out why (WN-50 without -Watch)' -f $s.Name); $gaveUp[$key] = 1 }; continue }
                $cmd = Start-Cmd $s $c.K; if (-not (Test-Path -LiteralPath (Join-Path $Cc.RunDir 'revert.ps1'))) { [void](Write-CcRevert) }
                if (Invoke-CcChange -Description ('start ' + $s.Name + ' (it went down)') -Action { & ([scriptblock]::Create($cmd)) } -Undo (Stop-Cmd $s)) { Write-CcShow -Color Green -Text ('  [+] started ' + $s.Name) }
                else { Write-CcShow -Color Red -Text ('  [x] could not start ' + $s.Name) }
                $tries[$key] = @($t + [DateTime]::Now)
            } elseif ($st -eq 'down' -and $s.Mode -eq 'Disabled' -and $AutoRestart) { Write-CcShow -Color Yellow -Text ('  [*] {0} is disabled: not started (run WN-50 to fix it)' -f $s.Name) }
        }
        if ($round -eq 1) { Write-CcShow -Color DarkGray -Text ('  watching {0} service(s): {1}' -f $check.Count, (($check | ForEach-Object { $_.Svc.Name }) -join ' ')) }
        if ($WatchCount -gt 0 -and $round -ge $WatchCount) { break }
        Start-Sleep -Seconds $Watch
    }
    Write-Host ('All results: ' + $Cc.RunDir)
    Complete-Cc
}

Write-CcHeader '2/4  checks'
foreach ($c in $check) { Check-One $c $false; Show-One $c }
$free = R-DiskFree
if ($free -lt 10) { Write-CcShow -Color Red -Text ('  [!] the system drive has {0}% free: services fail to write logs and temp files - free some space' -f $free) }
$down = @($check | Where-Object { $_.Result -ne 'up' -and -not $_.Unused })
if ($check.Count -gt 0 -and $down.Count -eq 0) { Write-CcShow -Color Green -Text '  [ok] every service checked is up' }

# ---- 3/4 Fixes -------------------------------------------------------------------------------
Write-CcHeader '3/4  fixes (Enter = the default in capitals)'
$order = @{ firewall = 1; kill = 2; enable = 3; start = 4; pool = 5; recovery = 6 }
$fixes = @(); foreach ($c in $check) { foreach ($f in @($c.Fixes | Sort-Object @{ Expression = { $order[$_.Kind] } })) { $fixes += New-Object PSObject -Property @{ C = $c; F = $f } } }
if ($fixes.Count -eq 0) { Write-CcShow -Color Green -Text $(if ($down.Count -gt 0) { '  [ok] nothing to fix here (the problems above need a hand: see each one)' } else { '  [ok] nothing to fix' }) }
# Restart-on-crash for many services: one question for all of them.
$rec = @($fixes | Where-Object { $_.F.Kind -eq 'recovery' })
$recAll = ''
if ($rec.Count -gt 2 -and -not ($Fix -contains 'recovery')) {
    $recAll = $(if (Read-CcAsk -Question ('{0} services do not restart by themselves when they crash ({1}). Set all of them to?' -f $rec.Count, (($rec | ForEach-Object { $_.C.Svc.Name }) -join ' ')) -Default Y -Yes 'yes, restart after 5 s, 10 s, 30 s' -No 'no, leave them as they are') { 'y' } else { 'n' })
}
foreach ($x in $fixes) {
    $f = $x.F
    if ($Fix -contains $f.Kind) { $f.Chosen = $true; continue }
    if ($f.Kind -eq 'recovery' -and $recAll) { $f.Chosen = ($recAll -eq 'y'); continue }
    $f.Chosen = Read-CcAsk -Question ('[{0}] {1}?' -f $f.Kind, $f.Text) -Default $f.Default.ToUpper() -Yes 'yes, do it' -No 'no, leave it'
}
$todo = @($fixes | Where-Object { $_.F.Chosen })
if ($todo.Count -gt 0 -and -not $Cc.Apply -and (Test-CcCanAsk)) {
    if (Read-CcAsk -Question ('Make these {0} fix(es) now?' -f $todo.Count) -Default N -Yes 'yes, fix them now' -No 'no, change nothing (dry run)') {
        $Cc.Apply = $true; if (-not $Fake) { Assert-CcAdmin }
    }
}

# ---- 4/4 Apply and check again ---------------------------------------------------------------
Write-CcHeader $(if ($Cc.Apply) { '4/4  fixing, then checking again' } else { '4/4  dry run: nothing is changed' })
$ok = 0; $bad = 0
if ($todo.Count -eq 0) { if ($fixes.Count -gt 0) { Write-CcShow -Color DarkGray -Text '  No fix chosen.' } }
elseif (-not $Cc.Apply) {
    foreach ($x in $todo) { Write-CcShow -Color Yellow -Text ('  [~] ' + $x.F.Text); $Cc.Would++; $x.F.Done = 'would' }
    Write-CcShow -Color DarkGray -Text '  Dry run: nothing was changed. Run again with -Apply.'
} else {
    [void](Write-CcRevert)
    foreach ($x in $todo) {
        $f = $x.F; $cmd = $f.Do
        if (Invoke-CcChange -Description $f.Text -Action { & ([scriptblock]::Create($cmd)) } -Undo $f.Undo) { $ok++; $f.Done = 'done'; Write-CcShow -Color Green -Text ('  [+] ' + $f.Text) }
        else { $bad++; $f.Done = 'FAILED'; Write-CcShow -Color Red -Text ('  [x] FAILED: ' + $f.Text + ' (see the log)') }
    }
    Write-CcShow -Text ''
    Write-CcShow -Text '  Checked again:'
    $fresh = @(R-Services); $fm = @{}; foreach ($s in $fresh) { $fm[(Lc $s.Name)] = $s }
    foreach ($c in $check) { $c.Applied = (($c.Fixes | Where-Object { $_.Chosen } | ForEach-Object { $_.Kind + ':' + $_.Done }) -join ' ') }
    $seenC = @{}
    foreach ($x in $todo) {
        $c = $x.C; if ($seenC.ContainsKey($c.Svc.Name)) { continue }; $seenC[$c.Svc.Name] = 1
        if ($fm.ContainsKey((Lc $c.Svc.Name))) { $c.Svc = $fm[(Lc $c.Svc.Name)] }
        Check-One $c $true
        $left = @($c.Problems | Where-Object { $_ -notlike '*restart by itself*' })
        if ($left.Count -eq 0) { $c.Result = 'up'; Write-CcShow -Color Green -Text ('  [ok] {0} is up' -f $c.Svc.Name) } else { Show-One $c }
    }
}

# ---- Summary ----------------------------------------------------------------------------------
$tab = New-CcTable -Name status -Columns @('service', 'what', 'state', 'start', 'ports', 'result', 'fixes')
foreach ($c in $check) { Add-CcTableRow -File $tab -Values @($c.Svc.Name, $c.Why, $c.Svc.State, $c.Svc.Mode, $(if ($c.K) { ($c.K.Ports -join ',') } else { '' }), $c.Result, $(if ($c.Applied) { $c.Applied } else { (($c.Fixes | Where-Object { $_.Chosen } | ForEach-Object { $_.Kind + ':' + $(if ($_.Done) { $_.Done } else { 'chosen' }) }) -join ' ') })) }
Format-CcTable -File $tab
$sum = @()
$sum += ('WN-50 Windows service recovery  {0}  {1}' -f [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm 'UTC'"), $(if ($Cc.Apply) { 'APPLIED' } else { 'DRY RUN' }))
$sum += ('Box: {0}   services checked: {1}   up: {2}   with a problem: {3}' -f $Box, $check.Count, @($check | Where-Object { $_.Result -eq 'up' }).Count, @($check | Where-Object { $_.Result -ne 'up' -and -not $_.Unused }).Count)
foreach ($c in @($check | Where-Object { $_.Result -ne 'up' -and -not $_.Unused })) { $sum += ('  DOWN {0}: {1}' -f $c.Svc.Name, $c.Result) }
if ($Cc.Apply -and $todo.Count -gt 0) { $sum += ('Fixes: {0} done, {1} failed' -f $ok, $bad) }
$sum += ''
$sum += 'Still red in scoring but up here? The firewall (WN-25 -Undo latest), the router, then the scoring address.'
[IO.File]::WriteAllLines((Join-Path $Cc.RunDir 'summary.txt'), [string[]]$sum)
Write-CcHeader 'summary'
foreach ($l in $sum) {
    $col = ''
    if ($l -like 'WN-50 *') { $col = 'Cyan' } elseif ($l -like '  DOWN*' -or ($l -like 'Fixes:*' -and $bad -gt 0)) { $col = 'Red' }
    Write-CcShow -Color $col -Text $l
}
Write-Host ('All results: ' + $Cc.RunDir)   # always shown, even with -Quiet
if ($bad -gt 0) { Complete-Cc -ExitCode 5 }
Complete-Cc
