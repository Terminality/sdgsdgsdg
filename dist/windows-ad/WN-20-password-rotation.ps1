# =============================================================================
# ID:       WN-20
# NAME:     Windows password rotation
# ROLE:     Windows / AD  (wave 2, first 15 minutes)
# KIND:     changes - dry run unless -Apply
# VERSION:  1.0.0
#
# PURPOSE
#   Default and leaked passwords are the red team's first way in.  This gives
#   every enabled account a new password - local accounts on any Windows box,
#   and every domain user when run on a domain controller - and writes the new
#   passwords to ONE file for the captain, never to the screen or the log.
#   Accounts the team must keep as they are can be left out (-Exclude, the
#   protected list), and chosen accounts can get chosen passwords (-Passwords).
#
# USAGE
#   powershell -NoProfile -ExecutionPolicy Bypass -File WN-20-password-rotation.ps1 -Out C:\bt-out              dry run
#   powershell ... WN-20-password-rotation.ps1 -Out C:\bt-out -Apply -Exclude mark.jacobs,admin
#   powershell ... WN-20-password-rotation.ps1 -Out C:\bt-out -Apply -Passwords C:\team\sheet.csv
#   Run in an elevated window; on a domain controller as a domain admin.
#
# OPTIONS
#   -Exclude a,b       never touch these accounts
#   -Users a,b         change only these accounts
#                      A name in -Exclude or -Users that is not an account
#                      here STOPS the script before anything changes: a typo
#                      would change the account you meant to keep
#   -IgnoreMissing     only warn about such names (one list for many boxes)
#   -Passwords FILE    chosen passwords: "account,password" lines.  Accounts
#                      not in the file get a random one.  Spaces around both
#                      are dropped.  Names not here, and disabled accounts,
#                      are listed and not changed
#   -Length N          random password length (default 16, at least 12)
#   -IncludeMe         also change the account running this script (skipped
#                      by default: you are logged in with it)
#   -IncludeDisabled   also give disabled accounts a new password (they stay
#                      disabled; useful if the red team may turn one back on)
#   -IncludeServices   also change accounts that run services, tasks or IIS
#                      app pools here, or have an SPN (skipped by default:
#                      changing them breaks those services until each one is
#                      given the new password too)
#   -LocalOnly         on a domain controller, the domain accounts are the
#                      only ones; on a member server or workstation this is
#                      the default anyway (domain accounts are changed on a DC)
#   -Print             also show the new passwords on screen at the end
#   Common options (-Apply, -Out, -Protected, -NoProtected, -ForceScored,
#   -Quiet, -DebugLog) come from the library.
#
# OUTPUTS  (under -Out, in WN-20_<host>_<UTC time>\)
#   accounts.csv          account,scope,state,action,note  (no passwords)
#   summary.txt           what was changed, skipped and why
#   passwords.csv         host,account,password,time - only with -Apply,
#                         readable by Administrators and SYSTEM only.  Give it
#                         to the captain, then delete it from this box
#   pending-password.csv  only while ONE account is being changed; left
#                         behind if the script is stopped at that moment:
#                         that account has either its old password or this one
#
# WHAT IT CHANGES  (only with -Apply)
#   Account passwords (ADSI SetPassword: WinNT for local accounts, LDAP for
#   domain accounts).  Nothing else: accounts are not enabled, disabled,
#   unlocked or forced to change their password at next logon (that would
#   break scored logins).  Old passwords cannot be put back - Windows keeps no
#   copy anyone can restore - so passwords.csv is the record.
#
# DEPENDS ON
#   WMI (local accounts, services), ADSI (WinNT and LDAP providers), schtasks.
#   All present on Windows 7 / Server 2008 R2 and later.  No AD module needed.
#   $env:BT_WN20_FAKE names a folder of stand-in accounts for the tests, so
#   they never touch a real account.
#
# TESTED ON
#   PowerShell 7 on Linux against stand-in accounts (tests/wn20.Tests.ps1).
#   NOT yet run on real Windows: run it on a throwaway VM first.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Accounts the scoring engine logs in with MUST be excluded or on the
#     protected list (type account), or scoring breaks.
#   - Service accounts are found only on THIS box (services, tasks, IIS app
#     pools) plus any domain account with an SPN.  A domain account used by a
#     service on ANOTHER box is not seen: exclude it by name.
#   - krbtgt, Guest, DefaultAccount and WDAGUtilityAccount are never changed
#     (krbtgt has its own two-step reset, WN-22).
#   - A password the domain policy rejects (too short, too simple, used
#     before) fails for that account only; the summary says so.
#   - Changing a password does not end sessions already open.
#
# DEBUGGING
#   -DebugLog shows how each account was classified and why.
#   Passwords are never in the log, even with -DebugLog.
# =============================================================================
param(
    [switch]$Apply, [string]$Out, [string]$Protected, [switch]$NoProtected,
    [switch]$ForceScored, [switch]$Quiet, [switch]$DebugLog,
    [string[]]$Exclude = @(),
    [string[]]$Users = @(),
    [switch]$IgnoreMissing,
    [string]$Passwords = '',
    [int]$Length = 16,
    [switch]$IncludeMe,
    [switch]$IncludeDisabled,
    [switch]$IncludeServices,
    [switch]$Print,
    [switch]$Help
)

if ($Help) {
    Write-Host 'WN-20 Windows password rotation - new passwords for every enabled account'
    Write-Host '  -Apply               make the changes (default: dry run)'
    Write-Host '  -Exclude a,b         never touch these accounts'
    Write-Host '  -Users a,b           change only these accounts'
    Write-Host '  -IgnoreMissing       warn instead of stopping when a name is not an account here'
    Write-Host '  -Passwords FILE      "account,password" lines to use instead of random ones'
    Write-Host '  -Length N            random password length (default 16)'
    Write-Host '  -IncludeMe -IncludeDisabled -IncludeServices -Print'
    Write-Host '  -Out DIR -Protected FILE -NoProtected -ForceScored -Quiet -DebugLog'
    exit 0
}

# >>> BT-LIB  (lib/lib.ps1 0.2.1 pasted in by tools/build.sh - edit lib/lib.ps1, not this copy)
# =============================================================================
# ID:       LB-02
# NAME:     PowerShell library (lib.ps1)
# ROLE:     Automation  (wave 0, foundation)
# VERSION:  0.2.1
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

$script:CcLibVersion = '0.2.1'

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
# Windows PowerShell 5.1 turns an empty list returned from a function into
# $null, and piping $null passes ONE blank item - which the typo check then
# reported as a missing account.  So: no function return, and blanks dropped.
$Exclude = @(@($Exclude) | Where-Object { $_ } | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
$Users = @(@($Users) | Where-Object { $_ } | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
if ($Length -lt 12) { Write-Host '-Length must be 12 or more'; exit 2 }
if ($Passwords -and -not (Test-Path -LiteralPath $Passwords)) { Write-Host "-Passwords: cannot read $Passwords"; exit 2 }

# ---- Start ------------------------------------------------------------------
Initialize-Cc -Id 'WN-20' -Name 'Windows password rotation' -Kind changes -Bound $PSBoundParameters
$Fake = $env:BT_WN20_FAKE
if ($Fake) { Write-CcLog -Level WARN -Message "TEST MODE: stand-in accounts from $Fake; no real account is read or changed" }
elseif ($Cc.Apply) { Assert-CcAdmin }
Use-CcRunDir
$os = Get-CcOsInfo
$IsDC = $os.IsDC
if ($Fake -and (Test-Path -LiteralPath (Join-Path $Fake 'is-dc'))) { $IsDC = $true }
function Lc2($s) { if ($null -eq $s) { return '' }; return ([string]$s).ToLower() }
$me0 = $env:USERNAME; if (-not $me0) { $me0 = $env:USER }
$Me = Lc2 $me0

# ---- Account sources ----------------------------------------------------------
# Every read and write of an account goes through these few functions, so the
# tests can swap in stand-ins ($env:BT_WN20_FAKE) without touching Windows.
#   account object: Name, Scope (local|domain), Sid, Disabled, Spn, Path

function Read-FakeCsv([string]$name) {
    $p = Join-Path $Fake $name
    if (-not (Test-Path -LiteralPath $p)) { return @() }
    return @([IO.File]::ReadAllLines($p) | ConvertFrom-Csv)
}

function Get-Accounts {
    if ($Fake) {
        return @(Read-FakeCsv 'accounts.csv' | ForEach-Object { New-Object PSObject -Property @{ Name = $_.name; Scope = $_.scope; Sid = $_.sid; Disabled = ($_.disabled -eq 'True'); Spn = $_.spn; Path = $_.name } })
    }
    $list = @()
    if ($IsDC) {
        # Domain users through LDAP; no AD module needed.
        $root = [ADSI]'LDAP://RootDSE'
        $s = New-Object DirectoryServices.DirectorySearcher([ADSI]('LDAP://' + [string]$root.defaultNamingContext), '(&(objectCategory=person)(objectClass=user))')
        $s.PageSize = 1000
        foreach ($p in @('samaccountname', 'objectsid', 'useraccountcontrol', 'serviceprincipalname', 'distinguishedname')) { [void]$s.PropertiesToLoad.Add($p) }
        foreach ($r in @($s.FindAll())) {
            $sidBytes = $r.Properties['objectsid'][0]
            $sid = (New-Object Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
            $uac = [int]($r.Properties['useraccountcontrol'][0])
            $list += New-Object PSObject -Property @{ Name = [string]$r.Properties['samaccountname'][0]; Scope = 'domain'; Sid = $sid; Disabled = (($uac -band 2) -ne 0)
                Spn = ((@($r.Properties['serviceprincipalname']) | ForEach-Object { [string]$_ }) -join ' '); Path = ('LDAP://' + [string]$r.Properties['distinguishedname'][0]) }
        }
    } else {
        $q = @()
        if (Test-CcCommand 'Get-WmiObject') { $q = @(Get-WmiObject -Class Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop) }
        else { $q = @(Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop) }  # ps2-ok
        foreach ($u in $q) {
            $list += New-Object PSObject -Property @{ Name = $u.Name; Scope = 'local'; Sid = $u.SID; Disabled = [bool]$u.Disabled; Spn = ''; Path = ('WinNT://' + $env:COMPUTERNAME + '/' + $u.Name + ',user') }
        }
    }
    return $list
}

# Names of accounts that run something on this box: services, scheduled
# tasks and IIS application pools.  Changing their password breaks that
# service until it is given the new one.
function Get-ServiceUsers {
    $set = @{}
    function Add-One([string]$who, [string]$what) {
        $n = (Lc2 $who).Trim()
        if ($n -eq '') { return }
        if ($n.Contains('\')) { $n = $n.Substring($n.LastIndexOf('\') + 1) }
        if ($n.Contains('@')) { $n = $n.Substring(0, $n.IndexOf('@')) }
        if (@('localsystem', 'system', 'localservice', 'networkservice', 'local service', 'network service', 'n/a', 'users', 'interactive', 'everyone') -contains $n) { return }
        if ($n.StartsWith('nt service') -or $n.StartsWith('nt authority')) { return }
        if ($set.ContainsKey($n)) { $set[$n] += ', ' + $what } else { $set[$n] = $what }
    }
    if ($Fake) {
        foreach ($r in @(Read-FakeCsv 'service-users.csv')) { Add-One $r.account $r.what }
        return $set
    }
    try {
        $svc = @()
        if (Test-CcCommand 'Get-WmiObject') { $svc = @(Get-WmiObject -Class Win32_Service -ErrorAction Stop) } else { $svc = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop) }  # ps2-ok
        foreach ($s in $svc) { Add-One $s.StartName ('service ' + $s.Name) }
    } catch { Write-CcLog -Level WARN -Message ('could not list services: ' + $_.Exception.Message) }
    $hdr = @(); for ($i = 0; $i -lt 30; $i++) { $hdr += ('c' + $i) }
    $rows = @(Invoke-CcProgram -FilePath 'schtasks.exe' -Arguments @('/query', '/fo', 'csv', '/v') | Where-Object { $_ -match '^"' } | ConvertFrom-Csv -Header $hdr)
    $first = ''; if ($rows.Count -gt 0) { $first = $rows[0].c14 }
    foreach ($t in $rows) { if ($t.c14 -ne $first) { Add-One $t.c14 ('task ' + $t.c1) } }
    $ah = Join-Path $env:SystemRoot 'System32\inetsrv\config\applicationHost.config'
    if (Test-Path -LiteralPath $ah) {
        foreach ($m in [regex]::Matches([IO.File]::ReadAllText($ah), '<add name="([^"]+)"[^>]*>\s*<processModel[^>]*userName="([^"]+)"')) { Add-One $m.Groups[2].Value ('IIS app pool ' + $m.Groups[1].Value) }
    }
    return $set
}

# Set-Pw account password -> nothing, or throws with Windows' reason.
function Set-Pw($a, [string]$pw) {
    if ($Fake) {
        foreach ($r in @(Read-FakeCsv 'fail.csv')) { if ($r.name -eq $a.Name) { throw $r.reason } }
        if ($env:BT_WN20_SLOW -eq $a.Name) { Start-Sleep -Seconds 60 }
        [IO.File]::AppendAllText((Join-Path $Fake 'set.log'), ($a.Name + "`t" + $pw + "`n"))
        return
    }
    $o = [ADSI]$a.Path
    if ($a.Scope -eq 'domain') { [void]$o.psbase.Invoke('SetPassword', $pw); [void]$o.psbase.CommitChanges() }
    else { [void]$o.SetPassword($pw) }
}

# Test-Pw account password -> 'yes', 'no' or 'unknown' (cannot check here).
function Test-Pw($a, [string]$pw) {
    if ($Fake) {
        $last = ''
        foreach ($l in @([IO.File]::ReadAllLines((Join-Path $Fake 'set.log')))) { $f = $l -split "`t", 2; if ($f[0] -eq $a.Name) { $last = $f[1] } }
        if ($last -eq $pw) { return 'yes' }; return 'no'
    }
    try {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
        $ct = [DirectoryServices.AccountManagement.ContextType]::Machine
        if ($a.Scope -eq 'domain') { $ct = [DirectoryServices.AccountManagement.ContextType]::Domain }
        $pc = New-Object DirectoryServices.AccountManagement.PrincipalContext($ct)
        if ($pc.ValidateCredentials($a.Name, $pw)) { return 'yes' }
        return 'no'
    } catch { return 'unknown' }
}

# ---- Read accounts and decide ---------------------------------------------------
try { $accounts = @(Get-Accounts) } catch { Stop-Cc -Code 3 -Message ('cannot list the accounts: ' + $_.Exception.Message) }
if ($accounts.Count -eq 0) { Stop-Cc -Code 3 -Message 'no accounts found' }
$names = @{}; foreach ($a in $accounts) { $names[(Lc2 $a.Name)] = $a }

# Names typed by hand must exist: a typo in -Exclude would change the account
# the operator meant to keep.
$missing = @(@($Exclude) + @($Users) | Where-Object { $_ -and -not $names.ContainsKey((Lc2 $_)) })
if ($missing.Count -gt 0) {
    if ($IgnoreMissing) { Write-CcLog -Level WARN -Message ('not accounts here (ignored because of -IgnoreMissing): ' + ($missing -join ', ')) }
    else { Stop-Cc -Code 2 -Message ('no such account here: ' + ($missing -join ', ') + ' (named in -Exclude or -Users). Nothing was changed. Fix the spelling, or add -IgnoreMissing') }
}
$exL = @(@($Exclude) | Where-Object { $_ } | ForEach-Object { Lc2 $_ }); $usL = @(@($Users) | Where-Object { $_ } | ForEach-Object { Lc2 $_ })

# Chosen passwords.
$given = @{}; $notes = @()
if ($Passwords) {
    foreach ($l in @([IO.File]::ReadAllLines((Resolve-CcPath $Passwords)))) {
        $t = $l.Trim()
        if ($t -eq '' -or $t.StartsWith('#')) { continue }
        $i = $t.IndexOf(',')
        if ($i -lt 1) { continue }
        $n = $t.Substring(0, $i).Trim(); $p = $t.Substring($i + 1).Trim()
        if ($n -match '^(account|user|name)$') { continue }
        if ($p.Length -lt 8) { Stop-Cc -Code 2 -Message "-Passwords: the password for $n is shorter than 8 characters. Nothing was changed" }
        $given[(Lc2 $n)] = $p
        if (-not $names.ContainsKey((Lc2 $n))) { $notes += "$n is in -Passwords but is not an account here" }
    }
}

$svcUsers = Get-ServiceUsers
$never = @{ '500' = ''; '501' = 'Guest'; '502' = 'krbtgt: reset it with its own two-step process (WN-22)'; '503' = 'DefaultAccount (built in, unused)'; '504' = 'WDAGUtilityAccount (built in, unused)' }

$plan = @()
foreach ($a in ($accounts | Sort-Object Name)) {
    $ln = Lc2 $a.Name
    $rid = (([string]$a.Sid) -split '-')[-1]
    $act = 'change'; $why = ''
    if ($rid -ne '500' -and $never.ContainsKey($rid)) { $act = 'skip'; $why = 'never changed: ' + $never[$rid] }
    elseif ($ln -eq 'krbtgt' -or $ln -like 'krbtgt_*') { $act = 'skip'; $why = 'never changed: krbtgt (WN-22)' }
    elseif ($exL -contains $ln) { $act = 'skip'; $why = 'excluded (-Exclude)' }
    elseif ($usL.Count -gt 0 -and -not ($usL -contains $ln)) { $act = 'skip'; $why = 'not in -Users' }
    elseif ($ln -eq $Me -and -not $IncludeMe) { $act = 'skip'; $why = 'the account running this script (-IncludeMe to change it)' }
    elseif ($a.Disabled -and -not $IncludeDisabled) {
        $act = 'skip'; $why = 'disabled (-IncludeDisabled to change it anyway)'
    }
    elseif (-not $IncludeServices -and ($svcUsers.ContainsKey($ln) -or $a.Spn)) {
        $act = 'skip'; $what = $svcUsers[$ln]; if (-not $what) { $what = 'has an SPN: ' + $a.Spn }
        $why = "runs $what (changing it breaks that until the service gets the new password; -IncludeServices to change it)"
    }
    elseif (-not (Test-CcAllowed -Type account -Value $a.Name)) { $act = 'skip'; $why = 'on the protected list' }
    # A password asked for in -Passwords but not set must not go unnoticed.
    if ($act -eq 'skip' -and $given.ContainsKey($ln) -and $why -ne 'excluded (-Exclude)') { $notes += "$($a.Name) is in -Passwords but was NOT changed: $why" }
    $src = 'random'; if ($given.ContainsKey($ln)) { $src = 'from -Passwords' }
    $plan += New-Object PSObject -Property @{ A = $a; Act = $act; Why = $why; Src = $src }
    Write-CcLog -Level DEBUG -Message ('{0} ({1}): {2} {3}' -f $a.Name, $a.Scope, $act, $why)
}
foreach ($n in $notes) { Write-CcLog -Level WARN -Message $n }

# ---- Change -------------------------------------------------------------------
$csv = New-CcCsv -Name accounts -Header @('account', 'scope', 'state', 'action', 'note')
$pwFile = Join-Path $Cc.RunDir 'passwords.csv'
$pend = Join-Path $Cc.RunDir 'pending-password.csv'
$shown = @()
$changed = 0; $failed = 0; $would = 0; $skipped = 0

# Make a file readable by Administrators and SYSTEM only, with this header.
function New-Private([string]$p) {
    [IO.File]::WriteAllText($p, "host,account,password,time`r`n")
    if ((Test-CcWindows) -and (Test-CcCommand 'icacls.exe')) {
        [void](Invoke-CcProgram -FilePath 'icacls.exe' -Arguments @($p, '/inheritance:r', '/grant:r', '*S-1-5-32-544:F', '*S-1-5-18:F'))
    }
}
function Csv1([string]$s) { if ($s -match '[",]') { return '"' + $s.Replace('"', '""') + '"' }; return $s }

foreach ($x in $plan) {
    $a = $x.A
    $state = 'enabled'; if ($a.Disabled) { $state = 'disabled' }
    if ($x.Act -eq 'skip') { Add-CcCsvRow -File $csv -Values @($a.Name, $a.Scope, $state, 'skipped', $x.Why); $skipped++; continue }
    if (-not $Cc.Apply) {
        Write-CcLog -Level WOULD -Message ('set a new password ({0}) for {1} account {2}' -f $x.Src, $a.Scope, $a.Name)
        $Cc.Would++; $would++
        Add-CcCsvRow -File $csv -Values @($a.Name, $a.Scope, $state, 'would change', $x.Src)
        continue
    }
    $pw = $given[(Lc2 $a.Name)]
    if (-not $pw) { $pw = New-CcPassword -Length $Length }
    if (-not (Test-Path -LiteralPath $pwFile)) { New-Private $pwFile }
    # Written BEFORE the change and removed after it: if the script is
    # stopped in between, the password is not lost.
    New-Private $pend
    $line = ('{0},{1},{2},{3}' -f (Csv1 $Cc.Host), (Csv1 $a.Name), (Csv1 $pw), [DateTime]::UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"))
    [IO.File]::AppendAllText($pend, $line + "`r`n")
    $script:Why = ''
    $ok = Invoke-CcChange -Description ('set a new password ({0}) for {1} account {2}' -f $x.Src, $a.Scope, $a.Name) -Secret -Action {
        try { Set-Pw $a $pw } catch { $script:Why = $_.Exception.Message; if ($_.Exception.InnerException) { $script:Why = $_.Exception.InnerException.Message }; throw }
    }
    if ($ok) {
        [IO.File]::AppendAllText($pwFile, $line + "`r`n")
        Remove-Item -LiteralPath $pend -Force
        $chk = Test-Pw $a $pw
        $note = $x.Src; if ($chk -eq 'yes') { $note += '; new password tested' } elseif ($chk -eq 'no') { $note += '; WARNING: the new password did not work in a test logon - check this account' }
        Add-CcCsvRow -File $csv -Values @($a.Name, $a.Scope, $state, 'changed', $note)
        $changed++
        if ($Print) { $shown += ('  {0,-24} {1}' -f $a.Name, $pw) }
    } else {
        Remove-Item -LiteralPath $pend -Force
        $why = ($script:Why -replace '[\r\n]+', ' ').Trim()
        Write-CcLog -Level ERROR -Message ('{0}: not changed - {1}' -f $a.Name, $why)
        Add-CcCsvRow -File $csv -Values @($a.Name, $a.Scope, $state, 'FAILED', ('old password still in use: ' + $why))
        $failed++
    }
}

# ---- Summary ---------------------------------------------------------------------
$sum = @()
$sum += ('WN-20 Windows password rotation  {0}  {1}' -f [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm 'UTC'"), $(if ($Cc.Apply) { 'APPLIED' } else { 'DRY RUN' }))
$scope = 'local accounts'; if ($IsDC) { $scope = 'domain accounts (this is a domain controller)' }
$sum += ('Host: {0}   {1}' -f $Cc.Host, $scope)
$sum += ''
$sum += ('{0} changed, {1} would change, {2} failed, {3} skipped' -f $changed, $would, $failed, $skipped)
foreach ($r in @(Import-Csv -LiteralPath $csv)) {
    if ($r.action -eq 'skipped' -and $r.note -like 'never changed*') { continue }
    $sum += ('  {0,-12} {1,-24} {2}' -f $r.action, $r.account, $r.note)
}
if ($notes.Count -gt 0) { $sum += ''; $sum += 'Check:'; foreach ($n in $notes) { $sum += ('  ' + $n) } }
$sum += ''
if ($Cc.Apply -and (Test-Path -LiteralPath $pwFile)) {
    $sum += ('New passwords: ' + $pwFile)
    $sum += '  Give this file to the captain, then delete it from this box.'
    $sum += '  Services and scheduled tasks that log in as a changed account need the new password too.'
} elseif (-not $Cc.Apply) {
    $sum += 'Dry run: nothing was changed.  Check the list, then add -Apply.'
}
[IO.File]::WriteAllLines((Join-Path $Cc.RunDir 'summary.txt'), [string[]]$sum)
if (-not $Quiet) { foreach ($l in $sum) { Write-Host $l } }
if ($shown.Count -gt 0) { Write-Host ''; Write-Host 'New passwords (-Print):'; foreach ($l in $shown) { Write-Host $l } }
Write-Host ('All results: ' + $Cc.RunDir)
Complete-Cc
