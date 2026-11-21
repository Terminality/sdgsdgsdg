# =============================================================================
# ID:       WN-16
# NAME:     Windows web shell hunter
# ROLE:     Windows / AD  (wave 2, then any time the web site acts up)
# KIND:     changes - dry run unless -Apply (it only ever quarantines)
# VERSION:  1.0.0
#
# PURPOSE
#   Red team keeps coming back to a web site through a web shell: a small
#   page that runs their commands from a browser.  This looks in the site
#   folders of IIS (every site, application and virtual folder in
#   applicationHost.config), C:\inetpub\wwwroot, XAMPP and WAMP, and any
#   -WebRoot you name.  The Windows twin of SV-16.  It reads ASP.NET
#   (.aspx .ashx .asmx .ascx .cshtml), classic ASP (.asp .asa .cer), PHP,
#   JSP, web.config, and images and text files.
#
#     HIGH  request data run as code or a command (eval(Request..),
#           Execute Request(..), Process.Start with Request, system($_GET..))
#           code sent in the request loaded as a program (Assembly.Load)
#           eval of encoded code; a known web shell name
#           code in an upload or image folder; code inside an image or
#           text file; web.config with code in it, or one that makes image
#           or text files run as code
#     MED   code that runs programs (Process.Start, WScript.Shell, cmd /c,
#           powershell, shell_exec ...); Assembly.Load; a long base64 blob;
#           a program or script (.exe .bat .ps1 .vbs ...) in the site folder
#     LOW   a code file changed in the last -Hours hours (default 24)
#   The matching line is shown, so a real shell is easy to tell from a
#   normal page.  Then each HIGH and MED file is asked about: [q]uarantine
#   (moved out of the site; the undo puts it back) or [k]eep.  After
#   quarantining, the site must still load (-Url): if it loaded before and
#   does not now, the files are put back at once.
#
#   QUESTIONS (Enter takes the default in capitals; a parameter answers each):
#     another folder to scan?           -WebRoot DIR (Enter = none)
#     each file: [q]uarantine [k]eep [a]ll the rest: their default
#                (default q for HIGH, k for MED)
#     apply these changes?              -Apply (Enter = no: a dry run)
#
# USAGE
#   powershell -NoProfile -ExecutionPolicy Bypass -File WN-16-webshell-hunter.ps1               scan + dry run
#   powershell ... WN-16-webshell-hunter.ps1 -Apply                                            asks each
#   powershell ... WN-16-webshell-hunter.ps1 -Apply -Batch -Url http://127.0.0.1/order/
#   Run in an elevated window.
#
# OPTIONS
#   -WebRoot a,b       scan these folders too
#   -Hours N           "changed lately" means the last N hours (default 24)
#   -ShowLow           list the LOW files on screen too (always in findings.txt)
#   -Url a,b           pages that must still load after quarantining
#                      (default http://127.0.0.1/); -NoUrlCheck skips it
#   -Exclude a,b       paths (or parts of paths) never offered
#   -Timer SECONDS     revert countdown (default 120); -NoTimer
#   -Batch             no questions: the defaults (a dry run unless -Apply)
#   -NoColor           no colours
#   Common options (-Apply, -Out, -Protected, -NoProtected, -ForceScored,
#   -Quiet, -DebugLog) come from the library.
#
# OUTPUTS  (under -Out, one numbered folder per run: webshells-1, -2, ...)
#   output.txt      everything shown on screen, without colour
#   findings.txt    level, file, size, changed, reasons, the line, what was done
#   folders.txt     the folders scanned and where each came from
#   summary.txt     the summary page
#   run.txt, undo.txt, revert.ps1
#   The moved files: <Out>\quarantine\<host>\<time>_WN-16\ (full path kept)
#
# WHAT IT CHANGES  (only with -Apply, only the files you chose)
#   Each chosen file is moved into the run's quarantine folder, keeping its
#   full path and its SHA-256 in the log.  Nothing is deleted.  A path on the
#   protected list is never moved.
#
# DEPENDS ON
#   The file system and applicationHost.config (read as XML); a web request
#   (System.Net.HttpWebRequest) for the page check.  PowerShell 2.0 and
#   later.  $env:BT_WN16_FAKE names a folder holding a stand-in
#   applicationHost.config for the tests (%SystemDrive% means that folder):
#   then C:\inetpub, XAMPP and WAMP are not read, and the page check reads
#   site-needs.txt there (the site "loads" while every file listed exists).
#
# TESTED ON
#   PowerShell 7 on Linux against planted shells (tests/wn16.Tests.ps1).
#   NOT yet run on real Windows: run it on a throwaway VM first.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - A clever shell can avoid every pattern.  Read the LOW files too
#     (-ShowLow): a page changed in the last hours, on a site nobody edits.
#   - Compiled shells (a .dll in bin\) are not read; WN-42 and SH-06 look
#     at what runs.
#   - Admin pages and file managers run programs on purpose: MED for them
#     is normal.  Read the line before you quarantine.
#
# DEBUGGING
#   -DebugLog shows every folder and file read.
# =============================================================================
param(
    [switch]$Apply, [string]$Out, [string]$Protected, [switch]$NoProtected,
    [switch]$ForceScored, [switch]$Quiet, [switch]$DebugLog,
    [string[]]$WebRoot = @(),
    [int]$Hours = 24,
    [switch]$ShowLow,
    [string[]]$Url = @(),
    [switch]$NoUrlCheck,
    [string[]]$Exclude = @(),
    [int]$Timer = 120,
    [switch]$NoTimer,
    [switch]$Help,
    [switch]$Batch,
    [switch]$NoColor
)

if ($Help) {
    Write-Host 'WN-16 Windows web shell hunter - IIS, XAMPP and WAMP site folders: ASP.NET, ASP, PHP, JSP, web.config'
    Write-Host '  -WebRoot a,b    scan these folders too (asked; Enter = none)'
    Write-Host '  -Hours N        changed lately = the last N hours (24)   -ShowLow   list LOW files too'
    Write-Host '  -Url a,b        pages that must still load (http://127.0.0.1/)   -NoUrlCheck'
    Write-Host '  -Exclude a,b    paths never offered'
    Write-Host '  -Timer SECONDS -NoTimer -Batch -NoColor'
    Write-Host '  -Apply -Out DIR -Protected FILE -NoProtected -Quiet -DebugLog'
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
function Start-CcTimer {
    param([int]$Seconds = 120)
    $c = $script:Cc
    if (-not $c.Apply) { return }
    if (-not $c.RunDir) { Stop-Cc -Code 1 -Message 'Start-CcTimer needs Use-CcNumberedDir first' }
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
$WebRoot = Split-List $WebRoot; $Url = Split-List $Url
$Exclude = @(Split-List $Exclude | ForEach-Object { $_.ToLower() })
if ($Timer -lt 30) { Write-Host '-Timer must be 30 seconds or more'; exit 2 }
if ($Hours -lt 1) { Write-Host '-Hours must be 1 or more'; exit 2 }
if ($Url.Count -eq 0) { $Url = @('http://127.0.0.1/') }
foreach ($u in $Url) { if ($u -notmatch '^https?://') { Write-Host ("-Url '{0}' must start with http:// or https://" -f $u); exit 2 } }
function Lc($s) { if ($null -eq $s) { return '' }; return ([string]$s).ToLower() }

# ---- Start ------------------------------------------------------------------
Initialize-Cc -Id 'WN-16' -Name 'Windows web shell hunter' -Kind changes -Bound $PSBoundParameters
$Fake = $env:BT_WN16_FAKE
if ($Fake) { Write-CcLog -Level WARN -Message "TEST MODE: stand-in IIS config from $Fake" }
Use-CcNumberedDir 'webshells'
Write-CcShow -Color Cyan -Text ('WN-16 Windows web shell hunter | host {0} | results in {1}' -f $Cc.Host, $Cc.RunDir)
Write-CcLegend -Marks @('Red=[!] HIGH: looks like a web shell', 'Yellow=[*] MED: runs programs or hides code', 'DarkGray=[-] LOW: changed lately', 'Green=[+] quarantined')
if ($Cc.Apply -and -not $Fake) { Assert-CcAdmin }

# ---- 1/4 Where the sites are ----------------------------------------------------
Write-CcHeader '1/4  site folders and scanning'
$roots = New-Object System.Collections.ArrayList
function Add-Root([string]$p, [string]$from) {
    if (-not $p) { return }
    $p = $p.TrimEnd('\', '/'); if (-not $p) { return }
    foreach ($r in $roots) { if ((Lc $r.Path) -eq (Lc $p)) { return } }
    if (-not (Test-Path -LiteralPath $p -PathType Container)) { Write-CcLog -Level DEBUG -Message "not a folder: $p ($from)"; return }
    # A folder inside one already listed adds nothing; one around it replaces it.
    foreach ($r in @($roots)) { if ((Lc $p).StartsWith((Lc $r.Path) + '\') -or (Lc $p).StartsWith((Lc $r.Path) + '/')) { return } }
    foreach ($r in @($roots)) { if ((Lc $r.Path).StartsWith((Lc $p) + '\') -or (Lc $r.Path).StartsWith((Lc $p) + '/')) { [void]$roots.Remove($r) } }
    [void]$roots.Add((New-Object PSObject -Property @{ Path = $p; From = $from }))
}
$ahc = ''
if ($Fake) { $ahc = Join-Path $Fake 'applicationHost.config' }
elseif ($env:windir) { $ahc = Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config' }
if ($ahc -and (Test-Path -LiteralPath $ahc)) {
    try {
        [xml]$ahx = [IO.File]::ReadAllText($ahc)
        foreach ($s in @($ahx.configuration.'system.applicationHost'.sites.site)) {
            if (-not $s) { continue }
            foreach ($a in @($s.application)) {
                if (-not $a) { continue }
                foreach ($v in @($a.virtualDirectory)) {
                    if (-not $v -or -not $v.physicalPath) { continue }
                    $pp = [string]$v.physicalPath
                    if ($Fake) { $pp = $pp -replace '(?i)%SystemDrive%', $Fake -replace '\\', [string][IO.Path]::DirectorySeparatorChar }
                    else { $pp = [Environment]::ExpandEnvironmentVariables($pp) }
                    Add-Root $pp ('IIS site ' + $s.name + ' ' + $a.path)
                }
            }
        }
    } catch { Write-CcLog -Level WARN -Message ('applicationHost.config not read: ' + $_.Exception.Message) }
} else { Write-CcLog -Level DEBUG -Message 'no IIS configuration (applicationHost.config)' }
if (-not $Fake) {
    $sd = $env:SystemDrive; if (-not $sd) { $sd = 'C:' }
    foreach ($d in @('inetpub\wwwroot', 'xampp\htdocs', 'wamp\www', 'wamp64\www')) { Add-Root (Join-Path ($sd + '\') $d) 'a usual web folder' }
}
foreach ($w in $WebRoot) { Add-Root $w '-WebRoot' }
if ($WebRoot.Count -eq 0) {
    $more = Read-CcText -Question 'Another folder to scan (a site that is not in IIS)?' -Default '' -Hint 'a folder, e.g. D:\sites\order (Enter = none)'
    if ($more) { $before = $roots.Count; Add-Root $more 'typed'; if ($roots.Count -eq $before) { Write-CcShow -Color Yellow -Text ("  [*] {0}: not a folder, or already scanned" -f $more) } }
}
foreach ($r in $roots) { Write-CcShow -Text ('  {0}   ({1})' -f $r.Path, $r.From) }
$ftab = New-CcTable -Name folders -Columns @('folder', 'from')
foreach ($r in $roots) { Add-CcTableRow -File $ftab -Values @($r.Path, $r.From) }
Format-CcTable -File $ftab
if ($roots.Count -eq 0) {
    Write-CcShow -Color Yellow -Text '  [*] no site folders found: name one with -WebRoot'
}

# ---- What a web shell looks like -------------------------------------------------
# The patterns are built from pieces so antivirus does not take this script
# for a web shell.
$CodeExt = @('aspx', 'asp', 'ashx', 'asmx', 'ascx', 'asax', 'cshtml', 'vbhtml', 'asa', 'cer', 'cdx', 'php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar', 'jsp', 'jspx', 'shtml', 'cfm')
$ProgExt = @('exe', 'bat', 'cmd', 'ps1', 'vbs', 'vbe', 'hta', 'scr', 'js_', 'wsf', 'com')
$DataExt = @('jpg', 'jpeg', 'png', 'gif', 'bmp', 'ico', 'txt', 'svg')
$ev = 'ev' + 'al'; $ex = 'exe' + 'cute'; $rq = 'req' + 'uest'
$P = @(
    @('HIGH', ('\b(' + $ev + '|' + $ex + '|' + $ex + 'global)\s*\(?\s*' + $rq + '\b'), 'runs request data as code'),
    @('HIGH', ('(' + $ev + '|' + $ex + ')\s*\(.*"unsafe"'), 'one-line web shell (China Chopper style)'),
    @('HIGH', ('(process\.start|processstartinfo|wscript\.shell|\.exec\s*\(|\.run\s*\().*\b' + $rq + '|\b' + $rq + '\b.*(process\.start|processstartinfo|wscript\.shell)'), 'runs request data as a command'),
    @('HIGH', ('assembly\.load.*(' + $rq + '|frombase64string)|(' + $rq + '|frombase64string).*assembly\.load'), 'loads code sent in the request as a program'),
    @('HIGH', ('(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|assert|' + $ev + '|create_function)\s*\(\s*@?(stripslashes\s*\(\s*|base64_decode\s*\(\s*|trim\s*\(\s*)?\$_(get|post|request|cookie|server|files)'), 'runs request data as code or a command'),
    @('HIGH', ($ev + '\s*\(\s*@?(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|hex2bin|rawurldecode|convert_uudecode)'), $ev + ' of hidden (encoded) code'),
    @('HIGH', '\$_(get|post|request|cookie)\s*\[[^\]]*\]\s*\(', 'calls a function named by the request'),
    @('HIGH', ('runtime\.getruntime\(\)\.exec\s*\(.*' + $rq), 'runs request data as a command (JSP)'),
    @('HIGH', ('(aspx' + 'spy|ant' + 'sword|god' + 'zilla|be' + 'hinder|rebe' + 'yond|chop' + 'per|re' + 'georg|sharpy' + 'shell|tun' + 'na|c99' + 'shell|r57' + 'shell|wso shell|b374' + 'k|wee' + 'vely|files' + 'man|p0' + 'wny|alfa ?shell|web' + 'shell)'), 'known web shell name or code'),
    @('MED', '(shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(', 'runs programs'),
    @('MED', '(process\.start|processstartinfo|wscript\.shell|shell\.application|cmd(\.exe)?\s+/c|powershell(\.exe)?\s+-|runtime\.getruntime\(\)\.exec)', 'runs programs'),
    @('MED', 'assembly\.load', 'loads code at run time')
)
$ShellNames = '(aspx' + 'spy|ant' + 'sword|god' + 'zilla|be' + 'hinder|chop' + 'per|re' + 'georg|tun' + 'nel\.as|c99|r57|wso|b374' + 'k|p0' + 'wny|^cmd\.as|^shell\.(as|php|jsp)|^cmdasp)'
$CodeInData = '(<\?php|<%@|<%\s*(' + $ev + '|' + $ex + '|response)|runat\s*=\s*"?server|<script\s+language\s*=\s*"?(vb|j)script"?\s+runat)'
$UploadDir = '[\\/](upload|uploads|uploaded|userfiles|user_files|attachments|images|img|media|temp|tmp)[\\/]'
$Blob = New-Object Regex '[A-Za-z0-9+/=]{300,}'
$Rx = @(); foreach ($p in $P) { $Rx += ,@($p[0], (New-Object Regex $p[1], 'IgnoreCase'), $p[2]) }
$since = [DateTime]::Now.AddHours(-$Hours)

# ---- Scan -------------------------------------------------------------------------
$finds = New-Object System.Collections.ArrayList
$nFiles = 0
function Short([string]$s) { $s = $s.Trim(); if ($s.Length -gt 110) { $s = $s.Substring(0, 107) + '...' }; return $s }
function Scan-File($f, [string]$base) {
    $name = Lc $f.Name; $ext = ''; if ($name.Contains('.')) { $ext = $name.Substring($name.LastIndexOf('.') + 1) }
    $isCode = ($CodeExt -contains $ext); $isCfg = ($name -eq 'web.config'); $isProg = ($ProgExt -contains $ext); $isData = ($DataExt -contains $ext)
    if (-not ($isCode -or $isCfg -or $isProg -or $isData)) { return }
    $full = $f.FullName; $lp = Lc $full
    $rel = $lp; if ($lp.StartsWith((Lc $base))) { $rel = $lp.Substring($base.Length) }   # where in the site
    foreach ($e in $Exclude) { if ($lp.Contains($e)) { Write-CcLog -Level DEBUG -Message "-Exclude: $full"; return } }
    $script:nFiles++
    $why = New-Object System.Collections.ArrayList; $lvl = ''; $line = ''
    function Hit([string]$l, [string]$w, [string]$ln) {
        if (-not $why.Contains($w)) { [void]$why.Add($w) }
        $rank = @{ HIGH = 3; MED = 2; LOW = 1; '' = 0 }
        if ($rank[$l] -gt $rank[$script:lvlX]) { $script:lvlX = $l; if ($ln) { $script:lineX = $ln } }
        elseif ($ln -and -not $script:lineX) { $script:lineX = $ln }
    }
    $script:lvlX = ''; $script:lineX = ''
    if ($name -match $ShellNames) { Hit 'HIGH' 'known web shell file name' '' }
    if ($isProg -and $rel -notmatch '[\\/]bin[\\/]') { Hit 'MED' 'a program or script in the site folder' '' }
    if ($isCode -and $rel -match $UploadDir) { Hit 'HIGH' 'code in an upload or image folder' '' }
    if ($f.Length -le 3MB -and -not $isProg) {
        $lines = @(); try { $lines = [IO.File]::ReadAllLines($full) } catch { Write-CcLog -Level DEBUG -Message "not read: $full" }
        foreach ($ln in $lines) {
            if (-not $ln) { continue }
            if ($isData) { if ($ln -match $CodeInData) { Hit 'HIGH' 'code hidden inside an image or text file' (Short $ln) }; continue }
            if ($isCfg) {
                if ($ln -match '<%|runat\s*=\s*"?server') { Hit 'HIGH' 'web.config with code in it' (Short $ln) }
                if ($ln -match 'path\s*=\s*"\*\.(jpg|jpeg|png|gif|txt|ico|css|bmp|svg)"' -and $ln -match '(scriptprocessor|modules\s*=|type\s*=|handler)') { Hit 'HIGH' 'makes image or text files run as code' (Short $ln) }
                continue
            }
            foreach ($r in $Rx) { if ($r[1].IsMatch($ln)) { Hit $r[0] $r[2] (Short $ln) } }
            if ($ln.Length -gt 400 -and $Blob.IsMatch($ln)) { Hit 'MED' 'a long base64 blob' (Short $ln) }
        }
    }
    if (($isCode -or $isCfg) -and $f.LastWriteTime -gt $since) { Hit 'LOW' ('changed in the last ' + $Hours + ' hours') '' }
    if (-not $script:lvlX) { return }
    [void]$finds.Add((New-Object PSObject -Property @{ Level = $script:lvlX; Path = $full; Size = $f.Length; Changed = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm'); Why = ($why -join '; '); Line = $script:lineX; Done = '' }))
}
foreach ($r in $roots) {
    Write-CcLog -Level DEBUG -Message ('scanning ' + $r.Path)
    foreach ($f in @(Get-ChildItem -LiteralPath $r.Path -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer })) { Scan-File $f $r.Path }
}
$order = @{ HIGH = 1; MED = 2; LOW = 3 }
$sorted = @($finds | Sort-Object @{ Expression = { $order[$_.Level] } }, Path)
$nH = @($sorted | Where-Object { $_.Level -eq 'HIGH' }).Count; $nM = @($sorted | Where-Object { $_.Level -eq 'MED' }).Count; $nL = @($sorted | Where-Object { $_.Level -eq 'LOW' }).Count
Write-CcShow -Text ('  {0} file(s) read in {1} folder(s): {2} HIGH, {3} MED, {4} LOW' -f $nFiles, $roots.Count, $nH, $nM, $nL)
foreach ($x in $sorted) {
    if ($x.Level -eq 'LOW' -and -not $ShowLow) { continue }
    $c = @{ HIGH = 'Red'; MED = 'Yellow'; LOW = 'DarkGray' }[$x.Level]; $m = @{ HIGH = '[!]'; MED = '[*]'; LOW = '[-]' }[$x.Level]
    Write-CcShow -Color $c -Text ('  {0} {1,-4} {2} - {3}' -f $m, $x.Level, $x.Path, $x.Why)
    if ($x.Line) { Write-CcShow -Color DarkGray -Text ('        line: ' + $x.Line) }
}
if ($nL -gt 0 -and -not $ShowLow) { Write-CcShow -Color DarkGray -Text ('  {0} LOW file(s) (changed lately) are in findings.txt; -ShowLow lists them here' -f $nL) }
if ($nH + $nM -eq 0) { Write-CcShow -Color Green -Text '  [ok] nothing that looks like a web shell' }

# ---- 2/4 Questions ---------------------------------------------------------------
Write-CcHeader '2/4  questions (Enter = the default in capitals)'
$ask = @($sorted | Where-Object { $_.Level -ne 'LOW' })
$rest = $false
foreach ($x in $ask) {
    $d = 'k'; if ($x.Level -eq 'HIGH') { $d = 'q' }
    $ch = $d
    if (-not $rest -and (Test-CcCanAsk)) {
        $ch = Read-CcChoice -Question ('{0}: {1} ({2})?' -f $x.Level, $x.Path, $x.Why) -Default $d -Options @('q=quarantine it (moved out of the site; the undo puts it back)', 'k=keep it', 'a=all the rest: their default (HIGH quarantined, MED kept)')
        if ($ch -eq 'a') { $rest = $true; $ch = $d }
    } elseif (-not (Test-CcCanAsk)) { Write-CcShow -Color Cyan -Text ('[?] {0} -> {1} (default)' -f $x.Path, $(if ($d -eq 'q') { 'quarantine' } else { 'keep' })) }
    $x.Done = $(if ($ch -eq 'q') { 'chosen' } else { 'kept' })
}
$todo = @($ask | Where-Object { $_.Done -eq 'chosen' })
if ($todo.Count -gt 0 -and -not $Cc.Apply -and (Test-CcCanAsk)) {
    if (Read-CcAsk -Question ('Quarantine these {0} file(s) now?' -f $todo.Count) -Default N -Yes 'yes, move them out (a revert timer runs)' -No 'no, change nothing (dry run)') {
        if (-not $Cc.Protected -and -not $Cc.NoProtected) {
            Write-CcShow -Color Yellow -Text '[*] No protected list (the scored services, accounts and paths).'
            if (Read-CcAsk -Question 'Quarantine them without one?' -Default N -Yes 'yes, go on without a protected list' -No 'no, stop') { $Cc.NoProtected = $true; $Cc.Apply = $true }
        } else { $Cc.Apply = $true }
        if ($Cc.Apply -and -not $Fake) { Assert-CcAdmin }
    }
}

# ---- The page check ----------------------------------------------------------------
# Get-PageUp URL -> $true when the page answers with anything under 500.
function Get-PageUp([string]$u) {
    if ($Fake) {
        $need = Join-Path $Fake 'site-needs.txt'
        if (-not (Test-Path -LiteralPath $need)) { return $true }
        foreach ($p in @([IO.File]::ReadAllLines($need) | Where-Object { $_ })) { if (-not (Test-Path -LiteralPath $p)) { return $false } }
        return $true
    }
    try {
        $req = [Net.HttpWebRequest]::Create($u); $req.Timeout = 10000; $req.AllowAutoRedirect = $false; $req.Method = 'GET'
        $resp = $req.GetResponse(); $code = [int]$resp.StatusCode; $resp.Close(); return ($code -lt 500)
    } catch [Net.WebException] {
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode; return ($code -lt 500) }
        return $false
    } catch { return $false }
}
function Get-SiteUp { foreach ($u in $Url) { if (-not (Get-PageUp $u)) { return $false } }; return $true }

# ---- 3/4 Quarantine ----------------------------------------------------------------
Write-CcHeader $(if ($Cc.Apply) { '3/4  quarantining' } else { '3/4  dry run: nothing is changed' })
$ok = 0; $bad = 0; $back = 0
if ($todo.Count -eq 0) { Write-CcShow -Color Green -Text '  [ok] nothing to quarantine' }
elseif (-not $Cc.Apply) {
    foreach ($x in $todo) { Write-CcShow -Color Yellow -Text ('  [~] quarantine ' + $x.Path); $Cc.Would++; $x.Done = 'would quarantine' }
    Write-CcShow -Color DarkGray -Text '  Dry run: nothing was changed. Run again with -Apply.'
} else {
    $upBefore = $true
    if (-not $NoUrlCheck) { $upBefore = Get-SiteUp; if (-not $upBefore) { Write-CcShow -Color Yellow -Text ('  [*] the site does not load now ({0}): the check after quarantining is skipped' -f ($Url -join ' ')) } }
    if (-not $NoTimer) { Start-CcTimer -Seconds $Timer }
    $moved = @()
    foreach ($x in $todo) {
        if (-not (Test-CcAllowed -Type path -Value $x.Path)) { $x.Done = 'refused: protected path'; Write-CcShow -Color DarkGray -Text ('  [-] ' + $x.Path + ' - left (protected list)'); continue }
        $xx = $x
        if (Invoke-CcChange -Description ('quarantine ' + $x.Path) -Action { if (-not (Move-CcQuarantine -Path $xx.Path)) { throw 'quarantine failed' } }) {
            $ok++; $x.Done = 'quarantined'; $moved += $x; Write-CcShow -Color Green -Text ('  [+] quarantined ' + $x.Path)
        } else { $bad++; $x.Done = 'FAILED to quarantine'; Write-CcShow -Color Red -Text ('  [x] FAILED: ' + $x.Path) }
    }
    if ($moved.Count -gt 0 -and $upBefore -and -not $NoUrlCheck) {
        if (Get-SiteUp) { Write-CcShow -Color Green -Text ('  [ok] the site still loads ({0})' -f ($Url -join ' ')) }
        else {
            Write-CcShow -Color Red -Text '  [!] the site stopped loading: putting the files back'
            foreach ($x in $moved) {
                $rel = ((Resolve-CcPath $x.Path) -replace ':', '').TrimStart('\', '/'); $q = Join-Path $Cc.QuarDir $rel
                try { Move-Item -LiteralPath $q -Destination $x.Path -Force -ErrorAction Stop; $x.Done = 'put back: the site stopped loading'; $back++; $ok--; Write-CcShow -Color Yellow -Text ('  [~] put back ' + $x.Path) }
                catch { $x.Done = 'FAILED to put back: ' + $q; $bad++; Write-CcShow -Color Red -Text ('  [x] could not put back ' + $x.Path + ' (it is in ' + $q + ')') }
            }
            if (Get-SiteUp) { Write-CcShow -Color Green -Text '  [ok] the site loads again' } else { Write-CcShow -Color Red -Text '  [!] the site still does not load: it was not these files' }
        }
    }
}

# ---- 4/4 Summary -------------------------------------------------------------------
$tab = New-CcTable -Name findings -Columns @('level', 'file', 'size', 'changed', 'why', 'line', 'done')
foreach ($x in $sorted) { Add-CcTableRow -File $tab -Values @($x.Level, $x.Path, $x.Size, $x.Changed, $x.Why, $x.Line, $(if ($x.Done) { $x.Done } else { 'listed' })) }
Format-CcTable -File $tab
$sum = @()
$sum += ('WN-16 Windows web shell hunter  {0}  {1}' -f [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm 'UTC'"), $(if ($Cc.Apply) { 'APPLIED' } else { 'DRY RUN' }))
$sum += ('Folders: {0}   files read: {1}' -f $roots.Count, $nFiles)
$sum += ('Found: {0} HIGH, {1} MED, {2} LOW (changed in the last {3} hours; in findings.txt)' -f $nH, $nM, $nL, $Hours)
foreach ($x in $ask) { $sum += ('  {0,-4} {1}  -> {2}' -f $x.Level, $x.Path, $x.Done) }
if ($Cc.Apply -and $todo.Count -gt 0) { $sum += ''; $sum += ('Quarantined: {0}   Put back: {1}   Failed: {2}' -f $ok, $back, $bad); if ($ok -gt 0) { $sum += ('Moved to: ' + $Cc.QuarDir) } }
$sum += ''
$sum += 'Next: a shell means red team got in - WN-42 for what else they left, WN-20 for passwords, SH-06 -Profile triage for the logs.'
[IO.File]::WriteAllLines((Join-Path $Cc.RunDir 'summary.txt'), [string[]]$sum)
Write-CcHeader '4/4  summary'
foreach ($l in $sum) {
    $col = ''
    if ($l -like 'WN-16 *') { $col = 'Cyan' } elseif ($l -like '  HIGH*' -or $l -like '*FAILED*') { $col = 'Red' } elseif ($l -like '  MED*') { $col = 'Yellow' }
    Write-CcShow -Color $col -Text $l
}
if ($Cc.Apply -and $todo.Count -gt 0 -and -not $NoTimer) { [void](Complete-CcTimer) }
Write-Host ('All results: ' + $Cc.RunDir)   # always shown, even with -Quiet
if ($bad -gt 0) { Complete-Cc -ExitCode 5 }
Complete-Cc
