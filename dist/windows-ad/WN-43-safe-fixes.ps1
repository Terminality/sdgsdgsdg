# =============================================================================
# ID:       WN-43
# NAME:     Windows safe fixes
# ROLE:     Windows / AD  (wave 2, first 15 minutes)
# KIND:     changes - dry run unless -Apply; -Undo puts a run back
# VERSION:  1.0.0
#
# PURPOSE
#   Fixes the settings red teams weaken or hide in, choosing only fixes that
#   cannot break a scored service:
#     wdigest      passwords no longer kept readable in memory
#     smb1         SMBv1 server off (EternalBlue, relay)
#     zerologon    domain controllers: Netlogon secure channel enforced and
#                  the "vulnerable channel" allow-list removed
#     uac          UAC back on if someone turned it off
#     guest        Guest account disabled
#     debuggers    "debugger" backdoors removed: on sethc, utilman, osk and
#                  the other logon-screen programs always; on any other
#                  program when the debugger is a shell or in an odd folder
#     stickykeys   sethc / utilman / osk ... replaced by cmd or PowerShell are
#                  repaired from Windows' own copy (sfc /scanfile)
#     portproxy    port forwards (netsh interface portproxy) removed
#     defender     real-time protection on; exclusions and the policy keys
#                  that turn it off removed
#     eventlog     Windows Event Log service running and automatic
#     auditing     logon, account, group, process, task and policy changes
#                  audited; command lines and PowerShell logged; Security log
#                  at least 512 MB
#     anonymous    anonymous users cannot list accounts or use null sessions
#     lmhash       LM hashes no longer stored
#     installer    AlwaysInstallElevated off (machine and every user)
#     winlogon     Userinit and Shell back to Windows' own; stored logon
#                  password removed and auto-logon off
#     appinit      AppInit DLLs cleared and off
#     netsh        unknown netsh helper DLLs removed
#     wmi          WMI event subscriptions that run commands removed
#     hosts        hosts lines that redirect Microsoft, update or antivirus
#                  names removed (every other line kept)
#     llmnr        LLMNR off (its answers can be spoofed to steal hashes)
#   And, ONLY when named with -Include, fixes that MIGHT affect a service:
#     firewall     every firewall profile on (with the rules there are now)
#     latfp        LocalAccountTokenFilterPolicy off (remote admin with local
#                  accounts stops working)
#     ntlm         NTLMv2 only (LmCompatibilityLevel 5; very old clients fail)
#     lsappl       LSA protection (after reboot; some plug-ins stop loading)
#     rdpnla       RDP requires Network Level Authentication
#     spooler      Print Spooler stopped and disabled on a domain controller
#     remotereg    Remote Registry stopped and disabled
#     smbsigning   SMB signing required by the server (very old clients fail)
#
# USAGE
#   powershell -NoProfile -ExecutionPolicy Bypass -File WN-43-safe-fixes.ps1 -Out C:\bt-out                dry run
#   powershell ... WN-43-safe-fixes.ps1 -Out C:\bt-out -Apply                                            make the safe fixes
#   powershell ... WN-43-safe-fixes.ps1 -Out C:\bt-out -Apply -Include firewall,rdpnla                   plus two more
#   powershell ... WN-43-safe-fixes.ps1 -Out C:\bt-out -Undo latest                                      what undo would do
#   powershell ... WN-43-safe-fixes.ps1 -Out C:\bt-out -Undo latest -Apply                               put the last run back
#   Run in an elevated window.
#
# OPTIONS
#   -Only a,b         make only these fixes (names above)
#   -Skip a,b         make the safe fixes except these
#   -Include a,b      also make these "might affect a service" fixes
#   -Undo RUN         put back what a run changed: RUN is "latest" or a run
#                     folder (WN-43_<host>_<time>).  Dry run unless -Apply
#   -List             list the fixes and exit
#   Common options (-Apply, -Out, -Protected, -NoProtected, -Quiet, -DebugLog)
#   come from the library.  Protected services, ports and accounts are never
#   changed.
#
# OUTPUTS  (under -Out, in WN-43_<host>_<UTC time>\)
#   fixes.csv         fix,item,before,after,result
#   undo-plan.csv     every change in order, for -Undo (machine-readable)
#   backup\           registry keys, hosts file, WMI definitions as they were
#   summary.txt       what was fixed, already fine, skipped, failed
#   The host's undo log (undo-<host>.log) also gets a plain command per change.
#
# WHAT IT CHANGES  (only with -Apply)
#   The registry values, services, account flag, audit policy, Defender
#   settings, port forwards, WMI subscriptions, hosts lines and log size
#   listed above - nothing else.  Every change is recorded first in
#   undo-plan.csv; -Undo replays it backwards.  Two fixes are not undone on
#   purpose: a repaired sticky-keys program (undo would put the backdoor
#   back) and nothing else.  Some changes take effect after a reboot (UAC,
#   LSA protection, SMBv1 on Windows before 8 / 2012); the summary says which.
#
# DEPENDS ON
#   The registry, ADSI, WMI, auditpol, wevtutil, sfc, netsh (all Windows 7 /
#   2008 R2 and later).  Get/Set-SmbServerConfiguration and the Defender
#   cmdlets are used when present (Windows 8 / 2012 and later); otherwise the
#   registry.  $env:BT_WN43_FAKE names a folder of stand-in state for the
#   tests: then nothing on the machine is read or changed.
#
# TESTED ON
#   PowerShell 7 on Linux against stand-in state (tests/wn43.Tests.ps1):
#   every fix, a second run changing nothing, -Undo restoring the exact
#   starting state, protected items refused, failures.
#   NOT yet run on real Windows: run it on a throwaway VM first.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - It fixes what it finds now.  Run it again later: the red team comes back.
#   - Domain Group Policy can set some of these values back at the next policy
#     refresh (90 minutes).  Fix the GPO too (WN-38 / by hand).
#   - Tamper Protection blocks changes to Defender; those show as failed.
#   - -Undo restores what this script changed, not other scripts' changes.
#
# DEBUGGING
#   -DebugLog          shows every check and its value
#   fixes.csv          what each fix found and did
#   undo-plan.csv      exactly what -Undo will do
# =============================================================================
param(
    [switch]$Apply, [string]$Out, [string]$Protected, [switch]$NoProtected,
    [switch]$ForceScored, [switch]$Quiet, [switch]$DebugLog,
    [string]$Only = '',
    [string]$Skip = '',
    [string]$Include = '',
    [string]$Undo = '',
    [switch]$List,
    [switch]$Help
)

$SafeFixes = @('wdigest', 'smb1', 'zerologon', 'uac', 'guest', 'debuggers', 'stickykeys', 'portproxy', 'defender', 'eventlog', 'auditing', 'anonymous', 'lmhash', 'installer', 'winlogon', 'appinit', 'netsh', 'wmi', 'hosts', 'llmnr')
$ServiceFixes = @('firewall', 'latfp', 'ntlm', 'lsappl', 'rdpnla', 'spooler', 'remotereg', 'smbsigning')

if ($Help -or $List) {
    Write-Host 'WN-43 Windows safe fixes - dry run unless -Apply; -Undo RUN puts a run back'
    Write-Host ('  safe (made by default):      ' + ($SafeFixes -join ', '))
    Write-Host ('  only with -Include (service): ' + ($ServiceFixes -join ', '))
    Write-Host '  -Only a,b  -Skip a,b  -Include a,b  -Undo latest|RUNFOLDER  -List'
    Write-Host '  -Apply -Out DIR -Protected FILE -NoProtected -Quiet -DebugLog'
    exit 0
}

# >>> BT-LIB  (lib/lib.ps1 0.5.0 pasted in by tools/build.sh - edit lib/lib.ps1, not this copy)
# =============================================================================
# ID:       LB-02
# NAME:     PowerShell library (lib.ps1)
# ROLE:     Automation  (wave 0, foundation)
# VERSION:  0.5.0
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

$script:CcLibVersion = '0.5.0'

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
    foreach ($k in @('Apply','Quiet','DebugLog','ForceScored','NoProtected')) {
        if ($Bound.ContainsKey($k)) { $c[$k] = [bool]$Bound[$k] }
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
    else { $prot = Join-Path $out 'protected.csv' }
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
# File format (CSV with a header line; see config/protected.example.csv):
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
            $parts = $t -split ','
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
    if ($c.RunDir) { $file = Join-Path (Join-Path $c.RunDir 'raw') ($Name + '.txt') }
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
    if ($lo.Count + $cut -gt 0) { $out += ('All flags, including low: ' + $c.FlagsFile) }
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
#   Rule 15: the kit's hash is checked before each run.  If a MANIFEST.sha256
#   (written by tools/build.sh) sits in the script's folder or one of the two
#   folders above it, or $env:BT_MANIFEST points to one, the running script's
#   hash must match its line there.  A mismatch stops the script with exit 3:
#   the file on this host is not the one you built.
#   $env:BT_SKIP_VERIFY = '1' turns the check off (for development).
function Test-CcSelf {
    $c = $script:Cc
    if ($env:BT_SKIP_VERIFY -eq '1') { Write-CcLog -Level DEBUG -Message 'verify: skipped (BT_SKIP_VERIFY=1)'; return }
    if (-not $c.ScriptPath) { Write-CcLog -Level DEBUG -Message 'verify: script was not started from a file, nothing to hash'; return }
    $man = $env:BT_MANIFEST
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
    exit $ExitCode
}
# <<< BT-LIB

# ---- Options ----------------------------------------------------------------
# Lists are split inline, not by a function: Windows PowerShell 5.1 turns an
# empty list returned from a function into $null (found in WN-20).
$onlyL = @(@($Only -split '[,\s]+') | Where-Object { $_ } | ForEach-Object { $_.ToLower() })
$skipL = @(@($Skip -split '[,\s]+') | Where-Object { $_ } | ForEach-Object { $_.ToLower() })
$inclL = @(@($Include -split '[,\s]+') | Where-Object { $_ } | ForEach-Object { $_.ToLower() })
foreach ($n in @($onlyL + $skipL + $inclL)) {
    if (-not ($SafeFixes -contains $n) -and -not ($ServiceFixes -contains $n)) { Write-Host "unknown fix '$n' (see -List)"; exit 2 }
}
$Run = @()
if ($onlyL.Count -gt 0) { $Run = @($onlyL) } else { $Run = @($SafeFixes | Where-Object { -not ($skipL -contains $_) }) + @($inclL) }
foreach ($n in $onlyL) { if (($ServiceFixes -contains $n) -and -not ($inclL -contains $n)) { $inclL += $n } }

# ---- Start ------------------------------------------------------------------
Initialize-Cc -Id 'WN-43' -Name 'Windows safe fixes' -Kind changes -Bound $PSBoundParameters
$Fake = $env:BT_WN43_FAKE
if ($Fake) { Write-CcLog -Level WARN -Message "TEST MODE: stand-in state from $Fake; nothing on this machine is read or changed" }
else {
    # Several fixes use WMI objects' own methods (GetOwner, Delete, GetText),
    # which PowerShell 7 does not have.  Half a run is worse than none.
    if (-not (Test-CcCommand 'Get-WmiObject')) { Stop-Cc -Code 3 -Message 'run this with Windows PowerShell (powershell.exe, 5.1 or older), not PowerShell 7 (pwsh)' }
    if ($Cc.Apply) { Assert-CcAdmin }
}

function Lc($s) { if ($null -eq $s) { return '' }; return ([string]$s).ToLower() }
function Nz($s) { if ($null -eq $s) { return '' }; return [string]$s }
function Q([string]$s) { return "'" + $s.Replace("'", "''") + "'" }

# =============================================================================
# State providers.  Every read and write of the machine goes through these,
# so the tests can use stand-in state ($env:BT_WN43_FAKE) and never touch
# Windows.  Real mode uses the registry, ADSI, WMI and Windows' own tools.
# =============================================================================

function Fake-Path([string]$n) { return [IO.Path]::Combine($Fake, $n) }
function Fake-Read([string]$n) { $p = Fake-Path $n; if (-not (Test-Path -LiteralPath $p)) { return @() }; return @([IO.File]::ReadAllLines($p) | ConvertFrom-Csv) }
function Fake-Write([string]$n, [string[]]$header, $rows) {
    $lines = @(($header | ForEach-Object { '"' + $_ + '"' }) -join ',')
    foreach ($r in @($rows)) { $lines += (($header | ForEach-Object { '"' + (Nz $r.$_).Replace('"', '""') + '"' }) -join ',') }
    [IO.File]::WriteAllLines((Fake-Path $n), [string[]]$lines)
}

# ---- registry ----
function RPath([string]$k) { return 'Registry::' + ($k -replace '^HKLM\\', 'HKEY_LOCAL_MACHINE\' -replace '^HKU\\', 'HKEY_USERS\') }
# R-Get KEY NAME -> @{Type; Data} or $null.  Data is text; a multi-string is
# joined with ' | '.
function R-Get([string]$k, [string]$n) {
    if ($Fake) {
        foreach ($r in @(Fake-Read 'registry.csv')) { if ((Lc $r.key) -eq (Lc $k) -and (Lc $r.name) -eq (Lc $n)) { return @{ Type = $r.type; Data = $r.data } } }
        return $null
    }
    try { $key = Get-Item -LiteralPath (RPath $k) -ErrorAction Stop } catch { return $null }
    if (-not (@($key.GetValueNames()) -contains $n)) { return $null }
    $v = $key.GetValue($n, $null, 'DoNotExpandEnvironmentNames')
    $t = $key.GetValueKind($n).ToString()
    if ($v -is [string[]]) { $v = $v -join ' | ' }
    return @{ Type = $t; Data = [string]$v }
}
function R-Names([string]$k) {
    if ($Fake) { return @(Fake-Read 'registry.csv' | Where-Object { (Lc $_.key) -eq (Lc $k) } | ForEach-Object { $_.name }) }
    try { return @((Get-Item -LiteralPath (RPath $k) -ErrorAction Stop).GetValueNames()) } catch { return @() }
}
function R-SubKeys([string]$k) {
    if ($Fake) {
        $pre = (Lc $k) + '\'; $s = @{}
        foreach ($r in @(Fake-Read 'registry.csv')) { $lk = Lc $r.key; if ($lk.StartsWith($pre)) { $s[(($r.key.Substring($pre.Length)) -split '\\')[0]] = 1 } }
        return @($s.Keys)
    }
    try { return @((Get-Item -LiteralPath (RPath $k) -ErrorAction Stop).GetSubKeyNames()) } catch { return @() }
}
function R-Set([string]$k, [string]$n, [string]$type, [string]$data) {
    if ($Fake) {
        $rows = @(Fake-Read 'registry.csv' | Where-Object { -not ((Lc $_.key) -eq (Lc $k) -and (Lc $_.name) -eq (Lc $n)) })
        $rows += New-Object PSObject -Property @{ key = $k; name = $n; type = $type; data = $data }
        Fake-Write 'registry.csv' @('key', 'name', 'type', 'data') $rows; return
    }
    $p = RPath $k
    if (-not (Test-Path -LiteralPath $p)) { New-Item -Path $p -Force -ErrorAction Stop | Out-Null }
    $pt = 'String'; $val = [object]$data
    if ($type -eq 'DWord') { $pt = 'DWord'; $val = [int]$data }
    elseif ($type -eq 'MultiString') { $pt = 'MultiString'; $val = [string[]]@(@($data -split ' \| ') | Where-Object { $_ -ne '' }) }
    elseif ($type -eq 'ExpandString') { $pt = 'ExpandString' }
    New-ItemProperty -LiteralPath $p -Name $n -Value $val -PropertyType $pt -Force -ErrorAction Stop | Out-Null
}
function R-Del([string]$k, [string]$n) {
    if ($Fake) {
        Fake-Write 'registry.csv' @('key', 'name', 'type', 'data') @(Fake-Read 'registry.csv' | Where-Object { -not ((Lc $_.key) -eq (Lc $k) -and (Lc $_.name) -eq (Lc $n)) }); return
    }
    Remove-ItemProperty -LiteralPath (RPath $k) -Name $n -Force -ErrorAction Stop
}
# R-Export KEY FILE -> $true when saved (a key that does not exist is $false).
function R-Export([string]$k, [string]$file) {
    if ($Fake) {
        if ($env:BT_WN43_FAIL -eq 'export') { return $false }
        $pre = Lc $k
        $rows = @(Fake-Read 'registry.csv' | Where-Object { (Lc $_.key) -eq $pre -or (Lc $_.key).StartsWith($pre + '\') })
        if ($rows.Count -eq 0) { return $false }
        $lines = @('"key","name","type","data"') + @($rows | ForEach-Object { '"{0}","{1}","{2}","{3}"' -f $_.key, $_.name, $_.type, (Nz $_.data).Replace('"', '""') })
        [IO.File]::WriteAllLines($file, [string[]]$lines); return $true
    }
    [void](Invoke-CcProgram -FilePath 'reg.exe' -Arguments @('export', $k, $file, '/y'))
    $ok = ($LASTEXITCODE -eq 0); $global:LASTEXITCODE = 0
    return $ok
}
function R-Import([string]$k, [string]$file) {
    if ($Fake) {
        $pre = Lc $k
        $keep = @(Fake-Read 'registry.csv' | Where-Object { -not ((Lc $_.key) -eq $pre -or (Lc $_.key).StartsWith($pre + '\')) })
        $back = @([IO.File]::ReadAllLines($file) | ConvertFrom-Csv)
        Fake-Write 'registry.csv' @('key', 'name', 'type', 'data') (@($keep) + @($back)); return
    }
    [void](Invoke-CcProgram -FilePath 'reg.exe' -Arguments @('import', $file))
    if ($LASTEXITCODE -ne 0) { throw "reg import $file failed (exit $LASTEXITCODE)" }
}
function R-Users {
    if ($Fake) { return @(Fake-Read 'registry.csv' | ForEach-Object { if ($_.key -match '^HKU\\(S-1-5-21-[0-9-]+)\\') { $matches[1] } } | Select-Object -Unique) }
    try { return @([Microsoft.Win32.Registry]::Users.GetSubKeyNames() | Where-Object { $_ -match '^S-1-5-21-[0-9-]+$' }) } catch { return @() }
}

# ---- guest account ----
# Get-Guest -> @{ Name; Disabled } or $null.
function Get-Guest {
    if ($Fake) { foreach ($r in @(Fake-Read 'accounts.csv')) { if ($r.sid -like '*-501') { return @{ Name = $r.name; Disabled = ($r.disabled -eq 'True') } } }; return $null }
    # Filtered in WMI: without LocalAccount a member server lists the whole domain.
    $flt = "LocalAccount=True AND SID LIKE '%-501'"
    if ($IsDC) { $flt = "Domain='" + ($env:USERDOMAIN -replace "'", '') + "' AND SID LIKE '%-501'" }
    $g = @(Get-WmiObject -Class Win32_UserAccount -Filter $flt -ErrorAction Stop) | Select-Object -First 1
    if (-not $g) { return $null }
    return @{ Name = $g.Name; Disabled = [bool]$g.Disabled; Domain = $g.Domain }
}
function Set-GuestDisabled([bool]$off) {
    if ($Fake) {
        $rows = @(Fake-Read 'accounts.csv'); foreach ($r in $rows) { if ($r.sid -like '*-501') { $r.disabled = [string]$off } }
        Fake-Write 'accounts.csv' @('name', 'sid', 'disabled') $rows; return
    }
    $g = Get-Guest
    $u = [ADSI]('WinNT://' + $g.Domain + '/' + $g.Name + ',user')
    $flags = [int]$u.UserFlags.Value
    if ($off) { $flags = $flags -bor 2 } else { $flags = $flags -band (-bnot 2) }
    $u.UserFlags.Value = $flags
    $u.SetInfo()
}

# ---- SMB server ----
function Get-Smb1 {
    if ($Fake) { foreach ($r in @(Fake-Read 'smb.csv')) { if ($r.setting -eq 'EnableSMB1Protocol') { return ($r.value -eq 'True') } }; return $false }
    if (Test-CcCommand 'Get-SmbServerConfiguration') { return [bool](Get-SmbServerConfiguration).EnableSMB1Protocol }  # ps2-ok
    $v = R-Get "$CCS\Services\LanmanServer\Parameters" 'SMB1'
    if ($null -ne $v) { return ($v.Data -ne '0') }
    return ($Build -lt 16299)
}
# Set-Smb1 on|off -> 'now' when it took effect, 'reboot' when it needs one.
function Set-Smb1([bool]$on) {
    if ($Fake) { Fake-Write 'smb.csv' @('setting', 'value') @(New-Object PSObject -Property @{ setting = 'EnableSMB1Protocol'; value = [string]$on }); return 'now' }
    if (Test-CcCommand 'Set-SmbServerConfiguration') { Set-SmbServerConfiguration -EnableSMB1Protocol $on -Force -Confirm:$false -ErrorAction Stop; return 'now' }  # ps2-ok
    $v = '0'; if ($on) { $v = '1' }
    R-Set "$CCS\Services\LanmanServer\Parameters" 'SMB1' 'DWord' $v
    return 'reboot'
}

# ---- services ----
function Get-Svc([string]$name) {
    if ($Fake) { foreach ($r in @(Fake-Read 'services.csv')) { if ((Lc $r.name) -eq (Lc $name)) { return @{ Name = $r.name; State = $r.state; StartMode = $r.startmode } } }; return $null }
    $s = @(Get-WmiObject -Class Win32_Service -Filter ("Name='" + $name + "'") -ErrorAction Stop) | Select-Object -First 1
    if (-not $s) { return $null }
    return @{ Name = $s.Name; State = $s.State; StartMode = $s.StartMode }
}
# Set-Svc NAME MODE STATE   MODE Auto|Manual|Disabled, STATE Running|Stopped
function Set-Svc([string]$name, [string]$mode, [string]$state) {
    if ($Fake) {
        $rows = @(Fake-Read 'services.csv'); foreach ($r in $rows) { if ((Lc $r.name) -eq (Lc $name)) { $r.startmode = $mode; $r.state = $state } }
        Fake-Write 'services.csv' @('name', 'state', 'startmode') $rows; return
    }
    $st = @{ 'Auto' = 'Automatic'; 'Manual' = 'Manual'; 'Disabled' = 'Disabled' }[$mode]
    if ($state -eq 'Stopped') { Stop-Service -Name $name -Force -ErrorAction Stop }
    Set-Service -Name $name -StartupType $st -ErrorAction Stop
    if ($state -eq 'Running') { Start-Service -Name $name -ErrorAction Stop }
}
# Restart-Svc NAME -> restarts a running service.
function Restart-Svc([string]$name) {
    if ($Fake) { [IO.File]::AppendAllText((Fake-Path 'restarts.txt'), $name + "`n"); return }
    Restart-Service -Name $name -Force -ErrorAction Stop
}

# ---- Defender ----
# Get-Def -> @{ Realtime = 'on'|'off'|''; Paths; Processes; Extensions } ('' = no cmdlets)
function Get-Def {
    $d = @{ Realtime = ''; Paths = @(); Processes = @(); Extensions = @() }
    if ($Fake) {
        foreach ($r in @(Fake-Read 'defender.csv')) {
            if ($r.kind -eq 'realtime') { $d.Realtime = $r.value } else { $d[$r.kind] = @($d[$r.kind]) + @($r.value) }
        }
        return $d
    }
    if (-not (Test-CcCommand 'Get-MpPreference')) { return $d }  # ps2-ok (a name)
    $p = Get-MpPreference -ErrorAction Stop  # ps2-ok
    if ($p.DisableRealtimeMonitoring) { $d.Realtime = 'off' } else { $d.Realtime = 'on' }
    foreach ($k in @(@('Paths', 'ExclusionPath'), @('Processes', 'ExclusionProcess'), @('Extensions', 'ExclusionExtension'))) {
        $d[$k[0]] = @(@($p.($k[1])) | Where-Object { $_ -and ([string]$_) -notmatch '^N/A' } | ForEach-Object { [string]$_ })
    }
    return $d
}
function Set-DefRealtime([bool]$on) {
    if ($Fake) {
        if ($env:BT_WN43_FAIL -eq 'defrt') { throw 'Tamper Protection blocked the change (test)' }
        if ($env:BT_WN43_FAIL -eq 'defrt-silent') { return }
        $rows = @(Fake-Read 'defender.csv' | Where-Object { $_.kind -ne 'realtime' })
        $v = 'off'; if ($on) { $v = 'on' }
        $rows += New-Object PSObject -Property @{ kind = 'realtime'; value = $v }
        Fake-Write 'defender.csv' @('kind', 'value') $rows; return
    }
    Set-MpPreference -DisableRealtimeMonitoring (-not $on) -ErrorAction Stop  # ps2-ok
}
# Set-DefExclusion KIND VALUE add|remove   KIND Paths|Processes|Extensions
function Set-DefExclusion([string]$kind, [string]$value, [string]$how) {
    if ($Fake) {
        $rows = @(Fake-Read 'defender.csv' | Where-Object { -not ($_.kind -eq $kind -and $_.value -eq $value) })
        if ($how -eq 'add') { $rows += New-Object PSObject -Property @{ kind = $kind; value = $value } }
        Fake-Write 'defender.csv' @('kind', 'value') $rows; return
    }
    $param = @{ 'Paths' = 'ExclusionPath'; 'Processes' = 'ExclusionProcess'; 'Extensions' = 'ExclusionExtension' }[$kind]
    $a = @{}; $a[$param] = $value
    if ($how -eq 'add') { Add-MpPreference @a -ErrorAction Stop } else { Remove-MpPreference @a -ErrorAction Stop }  # ps2-ok
}

# ---- audit policy ----
function Get-Audit([string]$guid) {
    if ($Fake) { foreach ($r in @(Fake-Read 'auditpol.csv')) { if ($r.guid -eq $guid) { return $r.setting } }; return 'No Auditing' }
    $l = @(Invoke-CcProgram -FilePath 'auditpol.exe' -Arguments @('/get', ('/subcategory:' + $guid), '/r') | Where-Object { $_ -match '^[^,]*,' })
    if ($l.Count -lt 2) { return '' }
    return ((@($l[1] | ConvertFrom-Csv -Header @('m', 't', 's', 'g', 'i', 'e'))[0]).i)
}
function Set-AuditAll([string]$guid) {
    if ($Fake) {
        $rows = @(Fake-Read 'auditpol.csv' | Where-Object { $_.guid -ne $guid })
        $rows += New-Object PSObject -Property @{ guid = $guid; setting = 'Success and Failure' }
        Fake-Write 'auditpol.csv' @('guid', 'setting') $rows; return
    }
    [void](Invoke-CcProgram -FilePath 'auditpol.exe' -Arguments @('/set', ('/subcategory:' + $guid), '/success:enable', '/failure:enable'))
    if ($LASTEXITCODE -ne 0) { throw "auditpol /set failed (exit $LASTEXITCODE)" }
}
function Save-Audit([string]$file) {
    if ($Fake) { Copy-Item -LiteralPath (Fake-Path 'auditpol.csv') -Destination $file -Force; return }
    [void](Invoke-CcProgram -FilePath 'auditpol.exe' -Arguments @('/backup', ('/file:' + $file)))
    if ($LASTEXITCODE -ne 0) { throw "auditpol /backup failed (exit $LASTEXITCODE)" }
}
function Restore-Audit([string]$file) {
    if ($Fake) { Copy-Item -LiteralPath $file -Destination (Fake-Path 'auditpol.csv') -Force; return }
    [void](Invoke-CcProgram -FilePath 'auditpol.exe' -Arguments @('/restore', ('/file:' + $file)))
    if ($LASTEXITCODE -ne 0) { throw "auditpol /restore failed (exit $LASTEXITCODE)" }
}

# ---- event log size ----
function Get-LogMax([string]$log) {
    if ($Fake) { foreach ($r in @(Fake-Read 'logs.csv')) { if ($r.name -eq $log) { return [int64]$r.max } }; return 0 }
    foreach ($l in @(Invoke-CcProgram -FilePath 'wevtutil.exe' -Arguments @('gl', $log))) { if ($l -match '^\s*maxSize:\s*(\d+)') { return [int64]$matches[1] } }
    return 0
}
function Set-LogMax([string]$log, [int64]$bytes) {
    if ($Fake) {
        $rows = @(Fake-Read 'logs.csv' | Where-Object { $_.name -ne $log }); $rows += New-Object PSObject -Property @{ name = $log; max = [string]$bytes }
        Fake-Write 'logs.csv' @('name', 'max') $rows; return
    }
    [void](Invoke-CcProgram -FilePath 'wevtutil.exe' -Arguments @('sl', $log, ('/ms:' + $bytes)))
    if ($LASTEXITCODE -ne 0) { throw "wevtutil sl failed (exit $LASTEXITCODE)" }
}

# ---- WMI subscriptions ----
# Get-WmiSubs -> objects: Name, Class, Command, Mof (the definitions of the
# consumer, its bindings and filters, to put back with mofcomp).
function Get-WmiSubs {
    if ($Fake) { return @(Fake-Read 'wmi.csv' | ForEach-Object { New-Object PSObject -Property @{ Name = $_.name; Class = $_.class; Command = $_.command; Mof = ('fake:' + $_.name + '|' + $_.class + '|' + $_.command) } }) }
    $out = @()
    foreach ($cls in @('CommandLineEventConsumer', 'ActiveScriptEventConsumer')) {
        foreach ($c in @(Get-WmiObject -Namespace 'root\subscription' -Class $cls -ErrorAction SilentlyContinue)) {
            $cmd = ((Nz $c.ExecutablePath) + ' ' + (Nz $c.CommandLineTemplate) + ' ' + (Nz $c.ScriptText)).Trim()
            $mof = @('#pragma namespace("\\\\.\\root\\subscription")')
            $binds = @(Get-WmiObject -Namespace 'root\subscription' -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | Where-Object { [string]$_.Consumer -like ('*' + $c.Name + '*') })
            foreach ($b in $binds) { try { $f = [wmi]([string]$b.Filter); $mof += $f.psbase.GetText('Mof') } catch { } }
            $mof += $c.psbase.GetText('Mof')
            foreach ($b in $binds) { $mof += $b.psbase.GetText('Mof') }
            $out += New-Object PSObject -Property @{ Name = $c.Name; Class = $cls; Command = $cmd; Mof = ($mof -join "`r`n") }
        }
    }
    return $out
}
function Remove-WmiSub($s) {
    if ($Fake) { Fake-Write 'wmi.csv' @('name', 'class', 'command') @(Fake-Read 'wmi.csv' | Where-Object { $_.name -ne $s.Name }); return }
    $c = @(Get-WmiObject -Namespace 'root\subscription' -Class $s.Class -Filter ("Name='" + $s.Name.Replace("'", "\'") + "'") -ErrorAction Stop)[0]
    foreach ($b in @(Get-WmiObject -Namespace 'root\subscription' -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | Where-Object { [string]$_.Consumer -like ('*' + $s.Name + '*') })) {
        try { $f = [wmi]([string]$b.Filter); $b.psbase.Delete(); $f.psbase.Delete() } catch { $b.psbase.Delete() }
    }
    $c.psbase.Delete()
}
function Restore-WmiSub([string]$file) {
    if ($Fake) {
        $t = [IO.File]::ReadAllText($file).Trim(); $p = $t.Substring(5) -split '\|', 3
        $rows = @(Fake-Read 'wmi.csv'); $rows += New-Object PSObject -Property @{ name = $p[0]; class = $p[1]; command = $p[2] }
        Fake-Write 'wmi.csv' @('name', 'class', 'command') $rows; return
    }
    [void](Invoke-CcProgram -FilePath 'mofcomp.exe' -Arguments @($file))
    if ($LASTEXITCODE -ne 0) { throw "mofcomp failed (exit $LASTEXITCODE)" }
}

# ---- files: hosts and the logon-screen programs ----
function HostsPath { if ($Fake) { return (Fake-Path 'hosts') }; return (Join-Path $env:SystemRoot 'System32\drivers\etc\hosts') }
# Get-SysHash NAME -> sha256 of a program in System32 ('' if absent).
function Get-SysHash([string]$name) {
    if ($Fake) { foreach ($r in @(Fake-Read 'files.csv')) { if ($r.name -eq $name) { return $r.sha } }; return '' }
    $p = Join-Path (Join-Path $env:SystemRoot 'System32') $name
    if ($name -eq 'powershell.exe') { $p = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe' }
    if ($name -eq 'explorer.exe') { $p = Join-Path $env:SystemRoot 'explorer.exe' }
    if (-not (Test-Path -LiteralPath $p)) { return '' }
    return (Nz (Get-CcSha256 -Path $p))
}
function Repair-SysFile([string]$name) {
    if ($Fake) {
        if ($env:BT_WN43_FAIL -eq 'sfc') { return }
        $rows = @(Fake-Read 'files.csv'); foreach ($r in $rows) { if ($r.name -eq $name) { $r.sha = 'original-' + $name } }
        Fake-Write 'files.csv' @('name', 'sha') $rows; return
    }
    [void](Invoke-CcProgram -FilePath 'sfc.exe' -Arguments @(('/scanfile=' + (Join-Path (Join-Path $env:SystemRoot 'System32') $name))))
    # sfc's exit code is not a reliable verdict; the caller re-hashes the file.
    $global:LASTEXITCODE = 0
}

# ---- firewall profiles ----
function Get-FwStates {
    $st = @{}
    if ($Fake) { foreach ($r in @(Fake-Read 'firewall.csv')) { $st[$r.profile] = $r.state }; return $st }
    $prof = ''
    foreach ($l in @(Invoke-CcProgram -FilePath 'netsh.exe' -Arguments @('advfirewall', 'show', 'allprofiles', 'state'))) {
        if ($l -match '^(\S+) Profile Settings') { $prof = $matches[1] }
        elseif ($prof -and $l -match '^State\s+(\S+)') { $st[$prof] = $matches[1] }
    }
    return $st
}
function Set-FwState([string]$prof, [string]$state) {
    if ($Fake) {
        $rows = @(Fake-Read 'firewall.csv'); foreach ($r in $rows) { if ($r.profile -eq $prof) { $r.state = $state } }
        Fake-Write 'firewall.csv' @('profile', 'state') $rows; return
    }
    [void](Invoke-CcProgram -FilePath 'netsh.exe' -Arguments @('advfirewall', 'set', ((Lc $prof) + 'profile'), 'state', (Lc $state)))
    if ($LASTEXITCODE -ne 0) { throw "netsh advfirewall set failed (exit $LASTEXITCODE)" }
}

$CCS = 'HKLM\SYSTEM\CurrentControlSet'
$NT = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$CV = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion'
if ($Fake) {
    $IsDC = Test-Path -LiteralPath (Fake-Path 'is-dc')
    $Build = 17763
} else {
    $os = Get-CcOsInfo; $IsDC = $os.IsDC
    $Build = 0; [void][int]::TryParse([string]$os.Build, [ref]$Build)
}

# =============================================================================
# The undo plan.  Every change is written to undo-plan.csv BEFORE it is made,
# as one machine-readable step, so -Undo can replay the run backwards:
#   kind      arguments
#   regimport key, backup file          put a key back as it was (reg import)
#   regdel    key, value name           delete a value this run created
#   regset    key, name, type, data     put a value back (non-secret values)
#   svc       name, mode, state
#   guest     disabled True/False
#   smb1      True/False
#   defrt     on/off
#   defexcl   kind, value               add an exclusion back
#   audit     backup file
#   logmax    log, bytes
#   wmi       mof file
#   file      backup file, original path
#   fw        profile, state
# The same change also gets a plain command in the host's undo log.
# =============================================================================
$Exported = @{}
function Plan([string]$kind, [string]$a, [string]$b = '', [string]$c = '', [string]$d = '') {
    if (-not $Cc.Apply) { return }
    Add-CcCsvRow -File $script:PlanFile -Values @($kind, $a, $b, $c, $d)
}
function R-Exists([string]$k) {
    if ($Fake) { $pre = Lc $k; return (@(Fake-Read 'registry.csv' | Where-Object { (Lc $_.key) -eq $pre -or (Lc $_.key).StartsWith($pre + '\') }).Count -gt 0) }
    return (Test-Path -LiteralPath (RPath $k))
}
# Save-Key KEY -> backs the key up once per run and plans its restore.
#   $false when the key exists but could not be saved: then the caller must
#   NOT change it (there would be no way back).  A key that does not exist yet
#   needs no backup; the values created in it are planned as deletions.
function Save-Key([string]$k) {
    if (-not $Cc.Apply) { return $true }
    if ($Exported.ContainsKey((Lc $k))) { return $Exported[(Lc $k)] }
    $file = Join-Path $script:BackDir ((($k -replace '[\\/:*?"<>| ]', '_')) + '.reg')
    $ok = $true
    if (R-Exists $k) {
        if (R-Export $k $file) {
            Plan 'regimport' $k $file
            Add-CcUndo -Description "WN-43 restore registry key $k" -Command ('reg.exe import {0}' -f (Q $file))
        } else { $ok = $false; Write-CcLog -Level ERROR -Message "could not back up $k - it will not be changed" }
    }
    $Exported[(Lc $k)] = $ok
    return $ok
}

# ---- results ----------------------------------------------------------------
$script:Rows = @()
$script:Reboot = @()
# (fixes.csv is written at the end, so a result corrected by a later check -
# a fix that did not stick - is right in the file too.)
function Res([string]$fix, [string]$item, [string]$before, [string]$after, [string]$result) {
    $result = ($result -replace '[\r\n]+', ' ').Trim()
    $script:Rows += New-Object PSObject -Property @{ Fix = $fix; Item = $item; Before = $before; After = $after; Result = $result }
}

# Change FIX ITEM BEFORE AFTER { action }  -> does it (or would), records it.
#   (The block parameter is $doIt, not $action: variable names ignore case,
#   and inside Invoke-CcChange "$action" would find its own -Action.)
function Change([string]$fix, [string]$item, [string]$before, [string]$after, [scriptblock]$doIt) {
    $script:ChangeErr = ''
    $ok = Invoke-CcChange -Description ('{0}: {1}  ({2} -> {3})' -f $fix, $item, $before, $after) -Action {
        try { & $doIt } catch { $script:ChangeErr = $_.Exception.Message; throw }
    }
    if (-not $Cc.Apply) { Res $fix $item $before $after 'would fix'; return $true }
    if ($ok) { Res $fix $item $before $after 'fixed' } else { Res $fix $item $before $after ('FAILED: ' + $script:ChangeErr) }
    return $ok
}
function Fine([string]$fix, [string]$item, [string]$now) { Res $fix $item $now $now 'already fine'; Write-CcLog -Level DEBUG -Message "$fix ${item}: already fine ($now)" }

# RegFix FIX KEY NAME TYPE WANT [-NotWhen v1,v2] [-OnlyWhen v1,v2]
#   Sets KEY\NAME to WANT unless it already is.  -OnlyWhen: change only when
#   the current value is one of these (missing = '(not set)').
function RegFix([string]$fix, [string]$k, [string]$n, [string]$type, [string]$want, [string[]]$OnlyWhen = @()) {
    $cur = R-Get $k $n
    $now = '(not set)'; if ($null -ne $cur) { $now = $cur.Data }
    if ($now -eq $want) { Fine $fix "$k\$n" $now; return }
    if ($OnlyWhen.Count -gt 0 -and -not ($OnlyWhen -contains $now)) { Fine $fix "$k\$n" $now; return }
    if (-not (Save-Key $k)) { Res $fix "$k\$n" $now $now 'FAILED: the key could not be backed up, so it was not changed'; $Cc.Failed++; return }
    if ($null -eq $cur) { Plan 'regdel' $k $n; Add-CcUndo -Description "WN-43 remove $k\$n" -Command ('Remove-ItemProperty -LiteralPath {0} -Name {1}' -f (Q (RPath $k)), (Q $n)) }
    [void](Change $fix "$k\$n" $now $want { R-Set $k $n $type $want })
}
# RegSetRaw FIX KEY NAME TYPE BEFORE WANT -> sets an existing value, key backed up first.
function RegSetRaw([string]$fix, [string]$k, [string]$n, [string]$type, [string]$before, [string]$want) {
    if (-not (Save-Key $k)) { Res $fix "$k\$n" $before $before 'FAILED: the key could not be backed up, so it was not changed'; $Cc.Failed++; return }
    [void](Change $fix "$k\$n" $before $want { R-Set $k $n $type $want })
}
# RegRemove FIX KEY NAME WHY -> deletes one value (the key backup restores it).
function RegRemove([string]$fix, [string]$k, [string]$n, [string]$shown) {
    if (-not (Save-Key $k)) { Res $fix "$k\$n" $shown $shown 'FAILED: the key could not be backed up, so it was not changed'; $Cc.Failed++; return }
    [void](Change $fix "$k\$n" $shown '(removed)' { R-Del $k $n })
}

# Folders almost nothing legitimate runs from, and shells: a debugger that is
# one of these is a backdoor.
$OddRe = '(\\users\\public\\|\\perflogs\\|\\windows\\temp\\|\\temp\\|\\appdata\\|\\programdata\\[^\\]+\.(exe|dll|bat|cmd|ps1|vbs)|\$recycle\.bin)'
$ShellRe = '(^|\\|")(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|explorer|taskmgr|nc|nc64|ncat)(\.exe)?("|\s|$)'
$LogonScreen = @('sethc.exe', 'utilman.exe', 'osk.exe', 'magnify.exe', 'narrator.exe', 'displayswitch.exe', 'atbroker.exe')

# =============================================================================
# The fixes
# =============================================================================

function F-wdigest { RegFix wdigest "$CCS\Control\SecurityProviders\WDigest" 'UseLogonCredential' 'DWord' '0' }

function F-smb1 {
    $on = Get-Smb1
    if (-not $on) { Fine smb1 'SMBv1 server' 'off'; return }
    if (-not (Test-CcAllowed -Type port -Value '445/tcp')) { Res smb1 'SMBv1 server' 'on' 'on' 'refused: 445/tcp is protected'; return }
    if ($Cc.Apply) { Plan 'smb1' 'True'; Add-CcUndo -Description 'WN-43 SMBv1 back on' -Command 'Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force' }  # ps2-ok (undo text; only run where the cmdlet exists)
    $script:Smb1How = ''
    if (Change smb1 'SMBv1 server' 'on' 'off' { $script:Smb1How = Set-Smb1 $false }) { if ($script:Smb1How -eq 'reboot') { $script:Reboot += 'SMBv1 off (registry; Windows before 8 / 2012)' } }
}

function F-zerologon {
    if (-not $IsDC) { Res zerologon 'Netlogon' '' '' 'not a domain controller'; return }
    RegFix zerologon "$CCS\Services\Netlogon\Parameters" 'FullSecureChannelProtection' 'DWord' '1'
    $v = R-Get "$CCS\Services\Netlogon\Parameters" 'vulnerable_channel_allowlist'
    if ($null -ne $v) { RegRemove zerologon "$CCS\Services\Netlogon\Parameters" 'vulnerable_channel_allowlist' 'set' }
}

function F-uac {
    $k = "$CV\Policies\System"
    $v = R-Get $k 'EnableLUA'
    if ($null -ne $v -and $v.Data -eq '0') { RegFix uac $k 'EnableLUA' 'DWord' '1'; $script:Reboot += 'UAC on' }
    else { Fine uac "$k\EnableLUA" (Nz $(if ($v) { $v.Data } else { '(not set: on)' })) }
}

function F-guest {
    $g = Get-Guest
    if (-not $g) { Res guest 'Guest' '' '' 'no Guest account'; return }
    if ($g.Disabled) { Fine guest $g.Name 'disabled'; return }
    if (-not (Test-CcAllowed -Type account -Value $g.Name)) { Res guest $g.Name 'enabled' 'enabled' 'refused: protected account'; return }
    if ($Cc.Apply) { Plan 'guest' 'False'; Add-CcUndo -Description "WN-43 enable $($g.Name) again" -Command ('net user {0} /active:yes' -f $g.Name) }
    [void](Change guest $g.Name 'enabled' 'disabled' { Set-GuestDisabled $true })
}

function F-debuggers {
    $base = "$NT\Image File Execution Options"
    $n = 0
    foreach ($p in @(R-SubKeys $base)) {
        $k = "$base\$p"
        $d = R-Get $k 'Debugger'
        if ($null -eq $d) { continue }
        $n++
        $bad = ($LogonScreen -contains (Lc $p)) -or ((Lc $d.Data) -match $ShellRe) -or ((Lc $d.Data) -match $OddRe)
        if ($bad) { RegRemove debuggers $k 'Debugger' $d.Data }
        else { Res debuggers "$k\Debugger" $d.Data $d.Data 'left: looks like a real tool (Process Explorer and the like); remove by hand if not yours' }
    }
    foreach ($p in @(R-SubKeys "$NT\SilentProcessExit")) {
        $k = "$NT\SilentProcessExit\$p"
        $m = R-Get $k 'MonitorProcess'
        if ($null -ne $m) { $n++; RegRemove debuggers $k 'MonitorProcess' $m.Data }
    }
    if ($n -eq 0) { Fine debuggers 'Image File Execution Options' 'no debugger keys' }
}

function F-stickykeys {
    $shells = @{}
    foreach ($s in @('cmd.exe', 'powershell.exe', 'explorer.exe')) { $h = Get-SysHash $s; if ($h) { $shells[$h] = $s } }
    $bad = 0
    foreach ($p in $LogonScreen) {
        $h = Get-SysHash $p
        if (-not $h) { continue }
        if ($shells.ContainsKey($h)) {
            $bad++
            $was = 'a copy of ' + $shells[$h]
            # Not undone on purpose: undo would put the backdoor back.
            if (Change stickykeys $p $was 'repaired by sfc' { Repair-SysFile $p }) {
                if ($Cc.Apply -and $shells.ContainsKey((Get-SysHash $p))) { $script:Rows[-1].Result = 'FAILED: sfc did not repair it'; $Cc.Failed++ }
            }
        }
    }
    if ($bad -eq 0) { Fine stickykeys 'logon-screen programs' 'not replaced' }
}

function F-portproxy {
    $base = "$CCS\Services\PortProxy"
    $n = 0; $rm = 0
    foreach ($t in @(R-SubKeys $base)) {
        foreach ($proto in @(R-SubKeys "$base\$t")) {
            $k = "$base\$t\$proto"
            foreach ($nm in @(R-Names $k)) {
                $n++
                $to = (R-Get $k $nm).Data
                $port = @($nm -split '/')[-1]
                if (-not (Test-CcAllowed -Type port -Value ($port + '/tcp'))) { Res portproxy "$t $nm" $to $to 'refused: protected port'; continue }
                RegRemove portproxy $k $nm ("$t $nm -> $to")
                $rm++
            }
        }
    }
    if ($n -eq 0) { Fine portproxy 'port forwards' 'none'; return }
    # The IP Helper service keeps a forward listening until it restarts, so
    # the registry alone does not stop it.  A restart takes a second and only
    # touches IPv6 transition (Teredo, 6to4, IP-HTTPS) and port forwards.
    if ($rm -gt 0) {
        $ih = Get-Svc 'iphlpsvc'
        if ($ih -and $ih.State -eq 'Running') {
            if (-not (Test-CcAllowed -Type service -Value 'iphlpsvc')) { Res portproxy 'iphlpsvc' 'running' 'running' 'refused: protected service - removed forwards stay live until it restarts' }
            else { [void](Change portproxy 'iphlpsvc (IP Helper)' 'running with the old forwards' 'restarted' { Restart-Svc 'iphlpsvc' }) }
        }
    }
}

function F-defender {
    $d = Get-Def
    foreach ($k in @('HKLM\SOFTWARE\Policies\Microsoft\Windows Defender', 'HKLM\SOFTWARE\Microsoft\Windows Defender')) {
        foreach ($n in @('DisableAntiSpyware', 'DisableAntiVirus')) { $v = R-Get $k $n; if ($null -ne $v -and $v.Data -ne '0') { RegRemove defender $k $n $v.Data } }
        foreach ($n in @('DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableOnAccessProtection')) { $v = R-Get "$k\Real-Time Protection" $n; if ($null -ne $v -and $v.Data -ne '0') { RegRemove defender "$k\Real-Time Protection" $n $v.Data } }
    }
    if ($d.Realtime -eq 'off') {
        if ($Cc.Apply) { Plan 'defrt' 'off'; Add-CcUndo -Description 'WN-43 Defender real-time back off' -Command 'Set-MpPreference -DisableRealtimeMonitoring $true' }  # ps2-ok (undo text)
        [void](Change defender 'real-time protection' 'off' 'on' { Set-DefRealtime $true })
    } elseif ($d.Realtime -eq 'on') { Fine defender 'real-time protection' 'on' }
    $n = 0
    foreach ($kind in @('Paths', 'Processes', 'Extensions')) {
        foreach ($v in @($d[$kind])) {
            if (-not $v) { continue }
            $n++
            if ($Cc.Apply) { Plan 'defexcl' $kind $v; Add-CcUndo -Description "WN-43 Defender exclusion back: $v" -Command ('Add-MpPreference -Exclusion{0} {1}' -f ($kind.TrimEnd('s') -replace 'Processe', 'Process'), (Q $v)) }
            [void](Change defender ("exclusion ($kind)") $v '(removed)' { Set-DefExclusion $kind $v 'remove' })
        }
    }
    # Tamper Protection can ignore these changes without an error: check.
    if ($Cc.Apply -and ($d.Realtime -eq 'off' -or $n -gt 0)) {
        $d2 = Get-Def
        if ($d.Realtime -eq 'off' -and $d2.Realtime -eq 'off') { foreach ($r in @($script:Rows | Where-Object { $_.Fix -eq 'defender' -and $_.Item -eq 'real-time protection' -and $_.Result -eq 'fixed' })) { $r.Result = 'FAILED: still off afterwards (Tamper Protection or another antivirus?)'; $Cc.Failed++ } }
        foreach ($kind in @('Paths', 'Processes', 'Extensions')) {
            foreach ($v in @($d2[$kind])) { if ($v) { foreach ($r in @($script:Rows | Where-Object { $_.Fix -eq 'defender' -and $_.Before -eq $v -and $_.Result -eq 'fixed' })) { $r.Result = 'FAILED: still there afterwards (Tamper Protection?)'; $Cc.Failed++ } } }
        }
    }
    # Exclusions set by policy live in the registry, not in Get-MpPreference.
    foreach ($kind in @('Paths', 'Processes', 'Extensions')) {
        $k = "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\$kind"
        foreach ($nm in @(R-Names $k)) { $n++; RegRemove defender $k $nm ('policy exclusion ' + $nm) }
    }
    if ($n -eq 0 -and $d.Realtime -eq '') { Res defender 'Defender' '' '' 'no Defender cmdlets (older Windows): policy keys only' }
}

function F-eventlog {
    $s = Get-Svc 'EventLog'
    if (-not $s) { Res eventlog 'EventLog' '' '' 'service not found'; return }
    if ($s.State -eq 'Running' -and $s.StartMode -eq 'Auto') { Fine eventlog 'EventLog' 'running, automatic'; return }
    if ($Cc.Apply) { Plan 'svc' 'EventLog' $s.StartMode $s.State; Add-CcUndo -Description 'WN-43 EventLog service back' -Command ('Set-Service EventLog -StartupType {0}' -f $s.StartMode) }
    [void](Change eventlog 'EventLog' ('{0}, {1}' -f $s.State, $s.StartMode) 'Running, Auto' { Set-Svc 'EventLog' 'Auto' 'Running' })
}

# Audit subcategories by GUID, so it works in every Windows language.
$AuditGuids = @(
    @('{0CCE9215-69AE-11D9-BED3-505054503030}', 'Logon'),
    @('{0CCE9216-69AE-11D9-BED3-505054503030}', 'Logoff'),
    @('{0CCE9217-69AE-11D9-BED3-505054503030}', 'Account Lockout'),
    @('{0CCE921B-69AE-11D9-BED3-505054503030}', 'Special Logon'),
    @('{0CCE922B-69AE-11D9-BED3-505054503030}', 'Process Creation'),
    @('{0CCE922F-69AE-11D9-BED3-505054503030}', 'Audit Policy Change'),
    @('{0CCE9235-69AE-11D9-BED3-505054503030}', 'User Account Management'),
    @('{0CCE9237-69AE-11D9-BED3-505054503030}', 'Security Group Management'),
    @('{0CCE923F-69AE-11D9-BED3-505054503030}', 'Credential Validation'),
    @('{0CCE9242-69AE-11D9-BED3-505054503030}', 'Kerberos Authentication Service'),
    @('{0CCE9211-69AE-11D9-BED3-505054503030}', 'Security System Extension'),
    @('{0CCE9227-69AE-11D9-BED3-505054503030}', 'Other Object Access Events (task creation)'),
    @('{0CCE923C-69AE-11D9-BED3-505054503030}', 'Directory Service Changes')
)
function F-auditing {
    $saved = $false
    foreach ($g in $AuditGuids) {
        if ($g[1] -eq 'Directory Service Changes' -and -not $IsDC) { continue }
        $cur = Get-Audit $g[0]
        if ($cur -eq 'Success and Failure') { Fine auditing $g[1] $cur; continue }
        if (-not $saved -and $Cc.Apply) {
            $f = Join-Path $script:BackDir 'audit-policy.csv'
            try { Save-Audit $f; Plan 'audit' $f; Add-CcUndo -Description 'WN-43 audit policy back' -Command ('auditpol /restore /file:{0}' -f (Q $f)); $saved = $true }
            catch { Res auditing 'audit policy' '' '' ('FAILED: could not back it up first, so not changed: ' + $_.Exception.Message); $Cc.Failed++; return }
        }
        [void](Change auditing $g[1] $cur 'Success and Failure' { Set-AuditAll $g[0] })
    }
    # Without this, an old-style (category) audit policy from Group Policy -
    # a DC's default policy has one - overwrites the settings above at the
    # next refresh.
    RegFix auditing "$CCS\Control\Lsa" 'SCENoApplyLegacyAuditPolicy' 'DWord' '1'
    RegFix auditing "$CV\Policies\System\Audit" 'ProcessCreationIncludeCmdLine_Enabled' 'DWord' '1'
    RegFix auditing 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 'DWord' '1'
    $max = Get-LogMax 'Security'; $want = [int64]512MB
    if ($max -ge $want) { Fine auditing 'Security log size' ('{0} MB' -f [int]($max / 1MB)) }
    elseif ($max -gt 0) {
        if ($Cc.Apply) { Plan 'logmax' 'Security' ([string]$max); Add-CcUndo -Description 'WN-43 Security log size back' -Command ('wevtutil sl Security /ms:{0}' -f $max) }
        [void](Change auditing 'Security log size' ('{0} MB' -f [int]($max / 1MB)) '512 MB' { Set-LogMax 'Security' $want })
    }
}

function F-anonymous {
    RegFix anonymous "$CCS\Control\Lsa" 'EveryoneIncludesAnonymous' 'DWord' '0'
    RegFix anonymous "$CCS\Control\Lsa" 'RestrictAnonymousSAM' 'DWord' '1'
    RegFix anonymous "$CCS\Services\LanmanServer\Parameters" 'RestrictNullSessAccess' 'DWord' '1'
    $ns = R-Get "$CCS\Services\LanmanServer\Parameters" 'NullSessionShares'
    if ($null -ne $ns -and $ns.Data.Trim() -ne '') { RegRemove anonymous "$CCS\Services\LanmanServer\Parameters" 'NullSessionShares' $ns.Data }
}

function F-lmhash { RegFix lmhash "$CCS\Control\Lsa" 'NoLMHash' 'DWord' '1' }

function F-installer {
    $v = R-Get 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated'
    if ($null -ne $v -and $v.Data -ne '0') { RegFix installer 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer' 'AlwaysInstallElevated' 'DWord' '0' }
    else { Fine installer 'AlwaysInstallElevated (machine)' 'off' }
    foreach ($u in @(R-Users)) {
        $k = "HKU\$u\Software\Policies\Microsoft\Windows\Installer"
        $v = R-Get $k 'AlwaysInstallElevated'
        if ($null -ne $v -and $v.Data -ne '0') { RegFix installer $k 'AlwaysInstallElevated' 'DWord' '0' }
    }
}

function F-winlogon {
    $k = "$NT\Winlogon"
    $ui = R-Get $k 'Userinit'
    $want = (Nz $env:SystemRoot); if (-not $want) { $want = 'C:\Windows' }; $want = $want + '\system32\userinit.exe,'
    if ($null -ne $ui) {
        $norm = ((Lc $ui.Data).Trim().TrimEnd(',') -replace '^%systemroot%', 'c:\windows' -replace '^%windir%', 'c:\windows')
        if ($norm -notmatch '^([a-z]:\\windows\\system32\\)?userinit\.exe$') { RegSetRaw winlogon $k 'Userinit' 'String' $ui.Data $want }
        else { Fine winlogon "$k\Userinit" $ui.Data }
    }
    $sh = R-Get $k 'Shell'
    if ($null -ne $sh -and (Lc $sh.Data).Trim() -ne 'explorer.exe' -and $sh.Data.Trim() -ne '') { RegSetRaw winlogon $k 'Shell' 'String' $sh.Data 'explorer.exe' }
    elseif ($null -ne $sh) { Fine winlogon "$k\Shell" $sh.Data }
    # A stored logon password is readable by any admin.  Its value is never
    # shown or logged; the key backup (admin-only) keeps it for -Undo.
    $dp = R-Get $k 'DefaultPassword'
    if ($null -ne $dp) {
        RegRemove winlogon $k 'DefaultPassword' '(set; value not shown)'
        $al = R-Get $k 'AutoAdminLogon'
        if ($null -ne $al -and $al.Data -ne '0') { RegSetRaw winlogon $k 'AutoAdminLogon' 'String' $al.Data '0' }
    } else { Fine winlogon "$k\DefaultPassword" 'not set' }
}

function F-appinit {
    $n = 0
    foreach ($k in @("$NT\Windows", 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows')) {
        $d = R-Get $k 'AppInit_DLLs'
        if ($null -ne $d -and $d.Data.Trim() -ne '') {
            $n++
            RegSetRaw appinit $k 'AppInit_DLLs' 'String' $d.Data ''
            $l = R-Get $k 'LoadAppInit_DLLs'
            if ($null -ne $l -and $l.Data -ne '0') { RegSetRaw appinit $k 'LoadAppInit_DLLs' 'DWord' $l.Data '0' }
        }
    }
    if ($n -eq 0) { Fine appinit 'AppInit_DLLs' 'empty' }
}

$DefaultNetsh = @('authfwcfg.dll', 'dhcpcmonitor.dll', 'dot3cfg.dll', 'fwcfg.dll', 'hnetmon.dll', 'ifmon.dll', 'napmontr.dll', 'netiohlp.dll', 'netprofm.dll', 'nettrace.dll', 'nshhttp.dll', 'nshipsec.dll', 'nshwfp.dll', 'p2pnetsh.dll', 'rasmontr.dll', 'rpcnsh.dll', 'wcnnetsh.dll', 'whhelper.dll', 'wlancfg.dll', 'wshelper.dll', 'wwancfg.dll', 'peerdistsh.dll', 'nshdnsclient.dll', 'mprmsg.dll', 'dhcpmonitor.dll', 'dhcpmon.dll', 'winsmon.dll', 'ipmontr.dll', 'ippromon.dll', 'ipxmontr.dll', 'ipxpromn.dll')
function F-netsh {
    $k = 'HKLM\SOFTWARE\Microsoft\NetSh'
    $n = 0
    foreach ($nm in @(R-Names $k)) {
        $v = (R-Get $k $nm).Data
        $leaf = Lc (@($v -split '[\\/]')[-1])
        if ($DefaultNetsh -contains $leaf) { continue }
        $n++
        RegRemove netsh $k $nm $v
    }
    if ($n -eq 0) { Fine netsh 'netsh helpers' 'only Windows ones' }
}

function F-wmi {
    $subs = @(Get-WmiSubs)
    if ($subs.Count -eq 0) { Fine wmi 'WMI subscriptions' 'none that run commands'; return }
    foreach ($s in $subs) {
        $file = Join-Path $script:BackDir ('wmi-' + ($s.Name -replace '[^A-Za-z0-9_.-]', '_') + '.mof')
        if ($Cc.Apply) {
            [IO.File]::WriteAllText($file, $s.Mof)
            Plan 'wmi' $file
            Add-CcUndo -Description "WN-43 WMI subscription back: $($s.Name)" -Command ('mofcomp {0}' -f (Q $file))
        }
        $sub = $s
        [void](Change wmi ('WMI ' + $s.Name) $s.Command '(removed)' { Remove-WmiSub $sub })
    }
}

$HostsBad = '(microsoft|windowsupdate|windows\.com|\bupdate\b|defender|virustotal|symantec|mcafee|kaspersky|sophos|crowdstrike|sentinelone|malwarebytes|eset|avast|bitdefender)'
function F-hosts {
    $p = HostsPath
    if (-not (Test-Path -LiteralPath $p)) { Res hosts 'hosts' '' '' 'no hosts file'; return }
    $lines = @([IO.File]::ReadAllLines($p))
    $keep = @(); $drop = @()
    foreach ($l in $lines) {
        $t = ($l -replace '#.*$', '').Trim()
        $f = @($t -split '\s+')
        if ($t -ne '' -and $f.Count -ge 2 -and (Lc (($f[1..($f.Count - 1)]) -join ' ')) -match $HostsBad) { $drop += $t } else { $keep += $l }
    }
    if ($drop.Count -eq 0) { Fine hosts 'hosts' 'no redirected Microsoft, update or antivirus names'; return }
    if ($Cc.Apply) {
        $bk = Join-Path $script:BackDir 'hosts'
        Copy-Item -LiteralPath $p -Destination $bk -Force
        Plan 'file' $bk $p
        Add-CcUndo -Description 'WN-43 hosts file back' -Command ('Copy-Item {0} {1} -Force' -f (Q $bk), (Q $p))
    }
    [void](Change hosts 'hosts' ($drop -join '; ') '(lines removed; every other line kept)' { [IO.File]::WriteAllLines($p, [string[]]$keep) })
}

function F-llmnr { RegFix llmnr 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 'DWord' '0' }

# ---- might affect a service: only with -Include --------------------------------
function F-firewall {
    $st = Get-FwStates
    if ($st.Count -eq 0) { Res firewall 'profiles' '' '' 'could not read the profiles (English netsh output expected)'; return }
    $n = 0
    foreach ($p in @('Domain', 'Private', 'Public')) {
        if (-not $st.ContainsKey($p)) { continue }
        if ($st[$p] -eq 'ON') { Fine firewall "$p profile" 'ON'; continue }
        $n++
        if ($Cc.Apply) { Plan 'fw' $p $st[$p]; Add-CcUndo -Description "WN-43 $p firewall profile back off" -Command ('netsh advfirewall set {0}profile state off' -f (Lc $p)) }
        $pp = $p
        [void](Change firewall "$p profile" $st[$p] 'ON' { Set-FwState $pp 'ON' })
    }
}
function F-latfp {
    $v = R-Get "$CV\Policies\System" 'LocalAccountTokenFilterPolicy'
    if ($null -ne $v -and $v.Data -ne '0') { RegFix latfp "$CV\Policies\System" 'LocalAccountTokenFilterPolicy' 'DWord' '0' } else { Fine latfp 'LocalAccountTokenFilterPolicy' 'off' }
}
function F-ntlm { RegFix ntlm "$CCS\Control\Lsa" 'LmCompatibilityLevel' 'DWord' '5' }
function F-lsappl {
    $v = R-Get "$CCS\Control\Lsa" 'RunAsPPL'
    if ($null -ne $v -and ($v.Data -eq '1' -or $v.Data -eq '2')) { Fine lsappl 'RunAsPPL' $v.Data; return }
    RegFix lsappl "$CCS\Control\Lsa" 'RunAsPPL' 'DWord' '1'; $script:Reboot += 'LSA protection'
}
function F-rdpnla { RegFix rdpnla "$CCS\Control\Terminal Server\WinStations\RDP-Tcp" 'UserAuthentication' 'DWord' '1' }
function SvcOff([string]$fix, [string]$name) {
    $s = Get-Svc $name
    if (-not $s) { Res $fix $name '' '' 'service not found'; return }
    if ($s.State -ne 'Running' -and $s.StartMode -eq 'Disabled') { Fine $fix $name 'stopped, disabled'; return }
    if (-not (Test-CcAllowed -Type service -Value $name)) { Res $fix $name $s.State $s.State 'refused: protected service'; return }
    if ($Cc.Apply) { Plan 'svc' $name $s.StartMode $s.State; Add-CcUndo -Description "WN-43 $name back" -Command ('Set-Service {0} -StartupType {1}; Start-Service {0}' -f $name, @{ 'Auto' = 'Automatic'; 'Manual' = 'Manual'; 'Disabled' = 'Disabled' }[$s.StartMode]) }
    [void](Change $fix $name ('{0}, {1}' -f $s.State, $s.StartMode) 'Stopped, Disabled' { Set-Svc $name 'Disabled' 'Stopped' })
}
function F-spooler { if (-not $IsDC) { Res spooler 'Spooler' '' '' 'not a domain controller: left alone'; return }; SvcOff spooler 'Spooler' }
function F-remotereg { SvcOff remotereg 'RemoteRegistry' }
function F-smbsigning { RegFix smbsigning "$CCS\Services\LanmanServer\Parameters" 'RequireSecuritySignature' 'DWord' '1' }

# =============================================================================
# -Undo: replay a run's undo-plan.csv backwards
# =============================================================================
function Invoke-Undo {
    $dir = $Undo
    if ($Undo -eq 'latest') {
        $cands = @(Get-ChildItem -LiteralPath $Cc.Out -Force | Where-Object { $_.PSIsContainer -and $_.Name -like ('WN-43_' + $Cc.Host + '_*') -and (Test-Path -LiteralPath (Join-Path $_.FullName 'undo-plan.csv')) -and -not (Test-Path -LiteralPath (Join-Path $_.FullName 'UNDONE')) } | Sort-Object Name)
        if ($cands.Count -eq 0) { Stop-Cc -Code 2 -Message "no WN-43 run with an undo plan (and not already undone) in $($Cc.Out)" }
        $dir = $cands[-1].FullName
    } elseif (-not (Test-Path -LiteralPath $dir)) {
        $try = Join-Path $Cc.Out $Undo
        if (Test-Path -LiteralPath $try) { $dir = $try } else { Stop-Cc -Code 2 -Message "-Undo: no run folder $Undo" }
    }
    $planF = Join-Path $dir 'undo-plan.csv'
    if (-not (Test-Path -LiteralPath $planF)) { Stop-Cc -Code 2 -Message "-Undo: $dir has no undo-plan.csv (was it a dry run?)" }
    if (Test-Path -LiteralPath (Join-Path $dir 'UNDONE')) { Stop-Cc -Code 2 -Message "-Undo: $dir was already undone" }
    $steps = @(Import-Csv -LiteralPath $planF)
    Write-CcLog -Level INFO -Message ('undo: {0} steps from {1}' -f $steps.Count, $dir)
    for ($i = $steps.Count - 1; $i -ge 0; $i--) {
        $s = $steps[$i]
        $desc = ('undo {0} {1} {2}' -f $s.kind, $s.a, $s.b).Trim()
        $act = $null
        switch ($s.kind) {
            'regimport' { $act = { R-Import $s.a $s.b; if ($s.a -like '*\Services\PortProxy*' -and (Get-Svc 'iphlpsvc') -and (Get-Svc 'iphlpsvc').State -eq 'Running') { Restart-Svc 'iphlpsvc' } } }
            'regdel'    { $act = { if ($null -ne (R-Get $s.a $s.b)) { R-Del $s.a $s.b } } }
            'svc'       { $act = { Set-Svc $s.a $s.b $s.c } }
            'guest'     { $act = { Set-GuestDisabled ($s.a -eq 'True') } }
            'smb1'      { $act = { [void](Set-Smb1 ($s.a -eq 'True')) } }
            'defrt'     { $act = { Set-DefRealtime ($s.a -eq 'on') } }
            'defexcl'   { $act = { Set-DefExclusion $s.a $s.b 'add' } }
            'audit'     { $act = { Restore-Audit $s.a } }
            'logmax'    { $act = { Set-LogMax $s.a ([int64]$s.b) } }
            'wmi'       { $act = { Restore-WmiSub $s.a } }
            'file'      { $act = { Copy-Item -LiteralPath $s.a -Destination $s.b -Force -ErrorAction Stop } }
            'fw'        { $act = { Set-FwState $s.a $s.b } }
            default     { Write-CcLog -Level WARN -Message "undo: unknown step $($s.kind)" }
        }
        if ($null -eq $act) { continue }
        [void](Invoke-CcChange -Description $desc -Action $act)
    }
    if ($Cc.Apply -and $Cc.Failed -eq 0) { [IO.File]::WriteAllText((Join-Path $dir 'UNDONE'), [DateTime]::UtcNow.ToString('o')) }
    if ($Cc.Apply -and $Cc.Failed -gt 0) { Write-CcLog -Level WARN -Message 'some undo steps failed; the run is not marked undone, so -Undo can be tried again' }
    Write-Host ('Undo of: ' + $dir)
    if (-not $Cc.Apply) { Write-Host 'Dry run: nothing was put back. Add -Apply.' }
    Complete-Cc
}

if ($Undo) { Invoke-Undo }

# =============================================================================
# Run the fixes
# =============================================================================
Use-CcRunDir
$script:BackDir = Join-Path $Cc.RunDir 'backup'
New-Item -ItemType Directory -Path $script:BackDir -Force | Out-Null
if ((Test-CcWindows) -and $Cc.Apply -and (Test-CcCommand 'icacls.exe')) {
    # The backup holds registry exports (a stored logon password among them).
    [void](Invoke-CcProgram -FilePath 'icacls.exe' -Arguments @($Cc.RunDir, '/inheritance:r', '/grant:r', '*S-1-5-32-544:(OI)(CI)F', '*S-1-5-18:(OI)(CI)F'))
}
$script:FixCsv = New-CcCsv -Name fixes -Header @('fix', 'item', 'before', 'after', 'result')
$script:PlanFile = Join-Path $Cc.RunDir 'undo-plan.csv'
if ($Cc.Apply) { [IO.File]::WriteAllText($script:PlanFile, "kind,a,b,c,d`r`n") }

foreach ($f in $Run) {
    try { & ('F-' + $f) }
    catch { Res $f '' '' '' ('FAILED: stopped: ' + $_.Exception.Message); $Cc.Failed++ }
}

foreach ($r in $script:Rows) { Add-CcCsvRow -File $script:FixCsv -Values @($r.Fix, $r.Item, $r.Before, $r.After, $r.Result) }

# ---- Summary ---------------------------------------------------------------------
$fixed = @($script:Rows | Where-Object { $_.Result -eq 'fixed' -or $_.Result -eq 'would fix' })
$bad = @($script:Rows | Where-Object { $_.Result -like 'FAILED*' })
$other = @($script:Rows | Where-Object { $_.Result -like 'refused*' -or $_.Result -like 'left*' })
$fine = @($script:Rows | Where-Object { $_.Result -eq 'already fine' })
$sum = @()
$sum += ('WN-43 Windows safe fixes  {0}  {1}' -f [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm 'UTC'"), $(if ($Cc.Apply) { 'APPLIED' } else { 'DRY RUN' }))
$sum += ('Host: {0}{1}   fixes run: {2}' -f $Cc.Host, $(if ($IsDC) { ' (domain controller)' } else { '' }), ($Run -join ', '))
$sum += ''
$verb = 'Fixed'; if (-not $Cc.Apply) { $verb = 'Would fix' }
$sum += ('{0} ({1}):' -f $verb, $fixed.Count)
foreach ($r in $fixed) { $sum += ('  {0,-11} {1}: {2} -> {3}' -f $r.Fix, $r.Item, $r.Before, $r.After) }
if ($bad.Count -gt 0) { $sum += ''; $sum += ('FAILED ({0}):' -f $bad.Count); foreach ($r in $bad) { $sum += ('  {0,-11} {1}: {2}' -f $r.Fix, $r.Item, $r.Result) } }
if ($other.Count -gt 0) { $sum += ''; $sum += 'Not changed, check:'; foreach ($r in $other) { $sum += ('  {0,-11} {1}: {2}' -f $r.Fix, $r.Item, $r.Result) } }
$sum += ''
$sum += ('Already fine: {0} checks' -f $fine.Count)
$notRun = @($ServiceFixes | Where-Object { -not ($Run -contains $_) })
if ($notRun.Count -gt 0) { $sum += ('Not run (might affect a service; add with -Include): ' + ($notRun -join ', ')) }
if ($script:Reboot.Count -gt 0) { $sum += ('Takes effect after a reboot: ' + (($script:Reboot | Select-Object -Unique) -join ', ')) }
if ($Cc.Apply -and $fixed.Count -gt 0) { $sum += ('To put this run back:  WN-43-safe-fixes.ps1 -Out ' + $Cc.Out + ' -Undo ' + (Split-Path -Leaf $Cc.RunDir) + ' -Apply') }
if (-not $Cc.Apply) { $sum += 'Dry run: nothing was changed. Check the list, then add -Apply.' }
[IO.File]::WriteAllLines((Join-Path $Cc.RunDir 'summary.txt'), [string[]]$sum)
if (-not $Quiet) { foreach ($l in $sum) { Write-Host $l } }
Write-Host ('All results: ' + $Cc.RunDir)
Complete-Cc
