# =============================================================================
# ID:       WN-35
# NAME:     Windows backup
# ROLE:     Windows / AD  (wave 1, first 15 minutes)
# KIND:     readonly - writes only into the output folder
# VERSION:  1.0.0
#
# PURPOSE
#   Run right after the collector (SH-06) and BEFORE any script that changes
#   the box.  It saves the settings a hardening step or the red team is most
#   likely to break, each with the command that puts it back, so a fix that
#   breaks a scored service can be undone in seconds:
#     every box      firewall rules, security policy and user rights, audit
#                    policy, scheduled tasks, hosts file, key registry areas,
#                    local users and group members (a list, not passwords)
#     when present   IIS settings and site files, DNS zones, DHCP settings;
#                    on a domain controller Group Policy, SYSVOL and a list of
#                    every user, group, computer and OU
#   It writes RESTORE.txt (what to run to put each item back), hashes every
#   saved file, and can copy the whole backup to another machine (-CopyTo),
#   because a red team with admin rights can delete a backup kept on the box.
#
# USAGE
#   powershell -NoProfile -ExecutionPolicy Bypass -File WN-35-backup.ps1 -Out C:\ccdc-out [options]
#   Run in an elevated window.  Without elevation most items fail and are
#   listed as failed.
#
# OPTIONS
#   -Path a,b         also back up these files or folders (application
#                     folders, config files, XAMPP ...)
#   -NoWebRoots       leave website files out (settings are still saved)
#   -MaxMB N          skip any single folder larger than N MB (default 500);
#                     it is listed as skipped, so you can add it by hand
#   -CopyTo DEST      copy the finished backup to DEST, a share or folder
#                     (\\10.0.0.5\backups).  A copy off the box survives a
#                     red team who deletes the one here
#   -AdDatabase       domain controller: also save the AD database with
#                     ntdsutil "IFM".  OFF by default: that copy holds every
#                     domain password hash.  Copy it off the box and delete it
#                     here, or do not make it at all
#   -Only a,b         run only these items (names from -List)
#   -List             list the items and exit
#   Common options (-Out, -DebugLog, -Quiet ...) come from the library.
#
# OUTPUTS  (under -Out, in WN-35_<host>_<UTC time>\)
#   items.csv         item,status,files,size_kb,detail - what was asked for
#                     and what happened
#   RESTORE.txt       the command to put back each item
#   SHA256SUMS.txt    hash of every saved file, to check a copy is intact
#   summary.txt       the same summary that is printed
#   registry\ firewall\ policy\ tasks\ files\ users\ iis\ web\ dns\ dhcp\
#   gpo\ sysvol\ ad\  the saved items
#
# WHAT IT CHANGES
#   Nothing on the host's settings.  It writes into the output folder only,
#   and limits that backup folder to Administrators and SYSTEM (icacls),
#   because registry exports and policy can hold sensitive values.  The DNS
#   zone export is written by dnscmd into %windir%\System32\dns and moved out
#   at once.  The AD Recycle Bin is NOT turned on (that cannot be undone);
#   its state is reported with the command to turn it on.
#
# DEPENDS ON
#   reg.exe, netsh, secedit, auditpol, icacls (every Windows); dnscmd (DNS
#   servers); netsh dhcp (DHCP servers); the GroupPolicy module (Backup-GPO)
#   and ADSI on domain controllers; ntdsutil for -AdDatabase.
#
# TESTED ON
#   Windows 11 (build 26200), Windows PowerShell 5.1, elevated: the eight
#   workstation items saved in 6 seconds.  PowerShell 7 on Linux with stand-in
#   programs (tests/wn35.Tests.ps1): every item's flow including IIS, DNS,
#   DHCP and DC items, RESTORE.txt, hashes, size limit, -CopyTo, failures.
#   NOT yet run on a real server or domain controller.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - Local password hashes are NOT saved (the SAM is not copied); restoring
#     an account means recreating it.  The users list is for comparison.
#   - The AD lists are for comparison; to bring back a deleted user use the
#     AD Recycle Bin (turn it on early) or an authoritative restore.
#   - A big web root can take minutes; -MaxMB and -NoWebRoots keep it short.
#   - Restoring the security policy (secedit /configure) puts back EVERY
#     setting in the file.  Read RESTORE.txt before running it.
#   - A 32-bit PowerShell on 64-bit Windows sees the 32-bit registry view.
#
# DEBUGGING
#   -DebugLog          each command and its exit code
#   items.csv          why an item failed (the program's own message)
#   -Only NAME         rerun one item
# =============================================================================
param(
    [switch]$Apply, [string]$Out, [string]$Protected, [switch]$NoProtected,
    [switch]$ForceScored, [switch]$Quiet, [switch]$DebugLog,
    [string[]]$Path = @(),
    [switch]$NoWebRoots,
    [int]$MaxMB = 500,
    [string]$CopyTo = '',
    [switch]$AdDatabase,
    [string]$Only = '',
    [switch]$List,
    [switch]$Help
)

$ItemHelp = @(
    'registry     key registry areas: services, startup, Winlogon, LSA, RDP, SMB, firewall, policies',
    'firewall     all firewall rules and profiles (netsh advfirewall export)',
    'secpolicy    security policy and user rights (secedit)',
    'auditpol     audit policy (auditpol /backup)',
    'tasks        every scheduled task (the XML files)',
    'hosts        the hosts file and other files in drivers\etc',
    'users        local users and group members (list only, no passwords)',
    'services     every service: state, start mode, program, account (list)',
    'iis          IIS settings (applicationHost.config and friends)',
    'web          website files of every IIS site (unless -NoWebRoots)',
    'dns          DNS server zones (dnscmd) and settings',
    'dhcp         DHCP server settings and leases (netsh dhcp export)',
    'gpo          every Group Policy object (Backup-GPO) - domain controllers',
    'sysvol       the SYSVOL folder (logon scripts, policies) - domain controllers',
    'ad           every AD user, group, computer and OU (list) - domain controllers',
    'addb         the AD database via ntdsutil IFM - only with -AdDatabase',
    'paths        files and folders given with -Path'
)
$AllItems = @('registry', 'firewall', 'secpolicy', 'auditpol', 'tasks', 'hosts', 'users', 'services', 'iis', 'web', 'dns', 'dhcp', 'gpo', 'sysvol', 'ad', 'addb', 'paths')

if ($Help) {
    Write-Host 'WN-35 Windows backup - saves settings and files before anything is changed'
    Write-Host '  -Path a,b       also back up these files or folders'
    Write-Host '  -NoWebRoots     leave website files out'
    Write-Host '  -MaxMB N        skip any single folder bigger than N MB (default 500)'
    Write-Host '  -CopyTo DEST    copy the backup to a share or folder'
    Write-Host '  -AdDatabase     DC: also save the AD database (holds every password hash)'
    Write-Host '  -Only a,b       run only these items (-List shows them)'
    Write-Host '  -Out DIR -Quiet -DebugLog  common options'
    exit 0
}
if ($List) { foreach ($l in $ItemHelp) { Write-Host $l }; exit 0 }

# >>> CCDC-LIB  (lib/lib.ps1 0.2.1 pasted in by tools/build.sh - edit lib/lib.ps1, not this copy)
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
#       # >>> CCDC-LIB
#       ...the loader lines from templates/script-template.ps1...
#       # <<< CCDC-LIB
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
#   $env:CCDC_ASSUME_YES = '1' answers yes without asking (for fan-out).
function Confirm-Cc {
    param([string]$Question)
    if ($env:CCDC_ASSUME_YES -eq '1') { return $true }
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
    elseif ($env:CCDC_OUT) { $out = $env:CCDC_OUT }
    else { $out = Join-Path $HOME 'ccdc-out' }
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
    elseif ($env:CCDC_PROTECTED) { $prot = $env:CCDC_PROTECTED }
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
#   folders above it, or $env:CCDC_MANIFEST points to one, the running script's
#   hash must match its line there.  A mismatch stops the script with exit 3:
#   the file on this host is not the one you built.
#   $env:CCDC_SKIP_VERIFY = '1' turns the check off (for development).
function Test-CcSelf {
    $c = $script:Cc
    if ($env:CCDC_SKIP_VERIFY -eq '1') { Write-CcLog -Level DEBUG -Message 'verify: skipped (CCDC_SKIP_VERIFY=1)'; return }
    if (-not $c.ScriptPath) { Write-CcLog -Level DEBUG -Message 'verify: script was not started from a file, nothing to hash'; return }
    $man = $env:CCDC_MANIFEST
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
# <<< CCDC-LIB

# ---- Options ----------------------------------------------------------------
$onlyList = @($Only -split '[,\s]+' | Where-Object { $_ -ne '' } | ForEach-Object { $_.ToLower() })
foreach ($n in $onlyList) { if (-not ($AllItems -contains $n)) { Write-Host "unknown item '$n' (see -List)"; exit 2 } }
if ($MaxMB -lt 1) { Write-Host '-MaxMB must be 1 or more'; exit 2 }
$Path = @($Path | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })

# Jp base 'a\b' -> base\a\b.  Join-Path refuses a drive that does not exist
# (C: when the tests run on Linux), and this also splits 'a\b' into parts.
function Jp([string]$a, [string]$b) { foreach ($part in @($b -split '[\\/]' | Where-Object { $_ -ne '' })) { $a = [IO.Path]::Combine($a, $part) }; return $a }

# ---- Start ------------------------------------------------------------------
Initialize-Cc -Id 'WN-35' -Name 'Windows backup' -Kind readonly -Bound $PSBoundParameters
Use-CcRunDir
$B = $Cc.RunDir
$IsAdmin = Test-CcAdmin
if (-not $IsAdmin) { Write-CcLog -Level WARN -Message 'not elevated: most items need an administrator window and will fail' }
$Win = $env:SystemRoot
if (-not $Win) { $Win = 'C:\Windows' }
$S32 = Jp $Win 'System32'
$os = Get-CcOsInfo

# Keep the backup readable by Administrators and SYSTEM only: registry and
# policy exports can hold sensitive values.
# Only when elevated: in a normal window the Administrators group is not
# active, and the folder would lock out the person who just made it.
if ($IsAdmin -or -not (Test-CcWindows)) { if (Test-CcCommand 'icacls.exe') {
    $o = @(Invoke-CcProgram -FilePath 'icacls.exe' -Arguments @($B, '/inheritance:r', '/grant:r', '*S-1-5-32-544:(OI)(CI)F', '*S-1-5-18:(OI)(CI)F'))
    if ($LASTEXITCODE -ne 0) { Write-CcLog -Level WARN -Message ('could not limit access to the backup folder: ' + ($o -join ' ')) }
} }

$ItemsCsv = New-CcCsv -Name items -Header @('item', 'status', 'files', 'size_kb', 'detail')
$script:Restore = @()
$script:Count = @{ ok = 0; failed = 0; skipped = 0 }
$script:Lines = @()

# Sub name -> <backup>\name, created.  (Not "Dir": that is an alias of Get-ChildItem.)
function Want([string]$item) { return ($onlyList.Count -eq 0 -or $onlyList -contains $item) }
function Sub([string]$name) { $d = Jp $B $name; if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }; return $d }
function Size([string]$p) {
    if (-not (Test-Path -LiteralPath $p)) { return 0 }
    $i = Get-Item -LiteralPath $p -Force
    if (-not $i.PSIsContainer) { return [int64]$i.Length }
    $sum = 0
    foreach ($f in @(Get-ChildItem -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer })) { $sum += $f.Length }
    return [int64]$sum
}
function Files([string]$p) { if (-not (Test-Path -LiteralPath $p)) { return 0 }; return @(Get-ChildItem -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer }).Count }

# Done item status where detail [restore lines]
#   status: ok | failed | skipped.  Every item ends with exactly one call.
function Done([string]$item, [string]$status, [string]$where = '', [string]$detail = '', [string[]]$restore = @()) {
    $n = 0; $kb = 0
    if ($where -and (Test-Path -LiteralPath $where)) { $n = Files $where; $kb = [int]((Size $where) / 1024) }
    Add-CcCsvRow -File $ItemsCsv -Values @($item, $status, $n, $kb, $detail)
    $script:Count[$status]++
    $mark = @{ ok = 'saved  '; failed = 'FAILED '; skipped = 'skipped' }[$status]
    $script:Lines += ('  {0} {1,-10} {2}' -f $mark, $item, $detail)
    $lvl = 'INFO'; if ($status -eq 'failed') { $lvl = 'WARN' }
    Write-CcLog -Level $lvl -Message ('{0}: {1} {2}' -f $item, $status, $detail)
    if ($status -eq 'ok' -and $restore.Count -gt 0) {
        $script:Restore += ''
        $script:Restore += ('## ' + $item)
        $script:Restore += $restore
    }
}

# Run program args -> $true when it exited 0.  Its output is kept in
# $script:LastOut for the item's detail.
function Run([string]$exe, [string[]]$a) {
    $script:LastOut = (@(Invoke-CcProgram -FilePath $exe -Arguments $a) -join ' ').Trim()
    Write-CcLog -Level DEBUG -Message ('{0} {1} -> exit {2}' -f $exe, ($a -join ' '), $LASTEXITCODE)
    return ($LASTEXITCODE -eq 0)
}
# Get-Wmi Class [Filter] -> objects (Get-CimInstance under PowerShell 7).
function Get-Wmi([string]$Class, [string]$Filter = '') {
    if (Test-CcCommand 'Get-WmiObject') {
        if ($Filter) { return Get-WmiObject -Class $Class -Filter $Filter -ErrorAction Stop }
        return Get-WmiObject -Class $Class -ErrorAction Stop
    }
    if ($Filter) { return Get-CimInstance -ClassName $Class -Filter $Filter -ErrorAction Stop }  # ps2-ok
    return Get-CimInstance -ClassName $Class -ErrorAction Stop  # ps2-ok
}
function Short([string]$s) { if ($s.Length -gt 160) { return $s.Substring(0, 157) + '...' }; return $s }
function Q([string]$p) { return '"' + $p + '"' }

# Copy-Tree src dest item -> copies a file or folder, honouring -MaxMB.
#   Returns 'ok', 'big' or an error message.
function Copy-Tree([string]$src, [string]$dest) {
    $mb = [int]((Size $src) / 1MB)
    if ($mb -gt $MaxMB) { return "big:$mb" }
    try {
        $parent = Split-Path -Parent $dest
        if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        Copy-Item -LiteralPath $src -Destination $dest -Recurse -Force -ErrorAction Stop
        return 'ok'
    } catch { return $_.Exception.Message }
}

# ---- Items ------------------------------------------------------------------

function I-registry {
    if (-not (Test-CcCommand 'reg.exe')) { Done registry skipped '' 'reg.exe not found (not Windows)'; return }
    $d = Sub 'registry'
    $keys = @(
        @('services', 'HKLM\SYSTEM\CurrentControlSet\Services'),
        @('run-hklm', 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'),
        @('runonce-hklm', 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'),
        @('run-wow64', 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'),
        @('policies-hklm', 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies'),
        @('policies-software', 'HKLM\SOFTWARE\Policies'),
        @('winlogon', 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'),
        @('ifeo', 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'),
        @('lsa', 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa'),
        @('securityproviders', 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders'),
        @('terminal-server', 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server'),
        @('session-manager', 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager'),
        @('netsh-helpers', 'HKLM\SOFTWARE\Microsoft\NetSh'),
        @('defender', 'HKLM\SOFTWARE\Microsoft\Windows Defender'),
        @('run-current-user', 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run')
    )
    $ok = 0; $bad = @(); $restore = @('# Each line puts one registry area back as it was (it ADDS and OVERWRITES values;', '# values created after the backup stay).  Run in an elevated window.')
    foreach ($k in $keys) {
        $f = Jp $d ($k[0] + '.reg')
        if (Run 'reg.exe' @('export', $k[1], $f, '/y')) { $ok++; $restore += ('reg import ' + (Q $f) + '    # ' + $k[1]) }
        elseif ($script:LastOut -notmatch 'unable to find|was unable|cannot find') { $bad += $k[1] }
    }
    if ($ok -eq 0) { Done registry failed $d ('no key could be exported: ' + (Short $script:LastOut)); return }
    $det = "$ok areas exported"; if ($bad.Count -gt 0) { $det += '; failed: ' + ($bad -join ', ') }
    Done registry ok $d $det $restore
}

function I-firewall {
    if (-not (Test-CcCommand 'netsh.exe')) { Done firewall skipped '' 'netsh not found (not Windows)'; return }
    $d = Sub 'firewall'
    $f = Jp $d 'firewall.wfw'
    if (-not (Run 'netsh.exe' @('advfirewall', 'export', $f))) { Done firewall failed $d (Short $script:LastOut); return }
    $txt = Jp $d 'profiles.txt'
    [IO.File]::WriteAllLines($txt, [string[]]@(Invoke-CcProgram -FilePath 'netsh.exe' -Arguments @('advfirewall', 'show', 'allprofiles')))
    Done firewall ok $d 'all rules and profile settings' @('# Replaces ALL current firewall rules and profile settings with the saved ones.', ('netsh advfirewall import ' + (Q $f)))
}

function I-secpolicy {
    if (-not (Test-CcCommand 'secedit.exe')) { Done secpolicy skipped '' 'secedit not found (not Windows)'; return }
    $d = Sub 'policy'
    $f = Jp $d 'security-policy.inf'
    if (-not (Run 'secedit.exe' @('/export', '/cfg', $f, '/quiet')) -or -not (Test-Path -LiteralPath $f)) { Done secpolicy failed $d (Short $script:LastOut); return }
    $db = Jp $d 'restore.sdb'
    Done secpolicy ok $d 'password and lockout policy, user rights, security options' @(
        '# Puts back EVERY setting in the file (password policy, user rights, security options).',
        '# Read the file first; to put back only the user rights add  /areas USER_RIGHTS',
        ('secedit /configure /db ' + (Q $db) + ' /cfg ' + (Q $f) + ' /overwrite /quiet'))
}

function I-auditpol {
    if (-not (Test-CcCommand 'auditpol.exe')) { Done auditpol skipped '' 'auditpol not found (not Windows)'; return }
    $d = Sub 'policy'
    $f = Jp $d 'audit-policy.csv'
    if (-not (Run 'auditpol.exe' @('/backup', ('/file:' + $f))) -or -not (Test-Path -LiteralPath $f)) { Done auditpol failed $d (Short $script:LastOut); return }
    Done auditpol ok $f 'every audit subcategory' @(('auditpol /restore /file:' + (Q $f)))
}

function I-tasks {
    $src = Jp $S32 'Tasks'
    if (-not (Test-Path -LiteralPath $src)) { Done tasks skipped '' "$src not found"; return }
    $d = Jp $B 'tasks'
    $r = Copy-Tree $src $d
    if ($r -ne 'ok') { Done tasks failed $d (Short $r); return }
    Done tasks ok $d 'every task definition (XML)' @(
        '# Put back one task (the name is its path under tasks\, with \ separators):',
        ('schtasks /create /tn "\TaskName" /xml ' + (Q (Jp $d 'TaskName')) + ' /f'),
        '# Compare with what exists now to find tasks the red team added:',
        ('Get-ChildItem -Recurse ' + (Q $d) + ' | Where-Object { -not $_.PSIsContainer } | ForEach-Object { $_.FullName.Substring(' + ($d.Length) + ') }'))
}

function I-hosts {
    $src = Jp $S32 'drivers\etc'
    if (-not (Test-Path -LiteralPath $src)) { Done hosts skipped '' "$src not found"; return }
    $d = Jp $B 'files\etc'
    $r = Copy-Tree $src $d
    if ($r -ne 'ok') { Done hosts failed $d (Short $r); return }
    Done hosts ok $d 'hosts, networks, protocol, services' @(('Copy-Item ' + (Q (Jp $d 'hosts')) + ' ' + (Q (Jp $src 'hosts')) + ' -Force'))
}

function Test-Wmi { return ((Test-CcCommand 'Get-WmiObject') -or (Test-CcCommand 'Get-CimInstance')) }  # ps2-ok (a name, not a call)
function I-users {
    if (-not (Test-Wmi)) { Done users skipped '' 'WMI not available (not Windows)'; return }
    $d = Sub 'users'
    $u = Jp $d 'local-users.csv'; $g = Jp $d 'group-members.csv'
    $ok = $false
    try {
        $rows = @(Get-Wmi Win32_UserAccount 'LocalAccount=True' | Select-Object Name, SID, Disabled, PasswordRequired, PasswordExpires, Description)
        [IO.File]::WriteAllLines($u, [string[]]@($rows | ConvertTo-Csv -NoTypeInformation))
        $lines = @('"group","member"')
        foreach ($gr in @(Get-Wmi Win32_Group 'LocalAccount=True')) {
            try {
                $obj = [ADSI]('WinNT://' + $gr.Domain + '/' + $gr.Name + ',group')
                foreach ($m in @($obj.psbase.Invoke('Members'))) {
                    $p = $m.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $m, $null)
                    $lines += ('"{0}","{1}"' -f $gr.Name, (($p -replace '^WinNT://', '') -replace '/', '\'))
                }
            } catch { }
        }
        [IO.File]::WriteAllLines($g, [string[]]$lines)
        $ok = $true
    } catch { $err = $_.Exception.Message }
    if (-not $ok) { Done users failed $d (Short $err); return }
    Done users ok $d ('{0} accounts; group members of every local group (no passwords)' -f $rows.Count) @('# A list for comparison: passwords are not saved.  Recreate a deleted account with:', 'net user NAME * /add', 'net localgroup GROUP NAME /add')
}

function I-services {
    if (-not (Test-Wmi)) { Done services skipped '' 'WMI not available (not Windows)'; return }
    $f = Jp (Sub 'services') 'services.csv'
    try {
        $rows = @(Get-Wmi Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName, StartName)
        [IO.File]::WriteAllLines($f, [string[]]@($rows | ConvertTo-Csv -NoTypeInformation))
    } catch { Done services failed '' (Short $_.Exception.Message); return }
    Done services ok $f ('{0} services' -f $rows.Count) @('# Service settings are in registry\services.reg.  To set one start mode back:', 'sc.exe config NAME start= auto      # or demand / disabled')
}

# IIS: settings folder, and the physical folders of every site.
$script:WebRoots = @()
function I-iis {
    $src = Jp $S32 'inetsrv\config'
    if (-not (Test-Path -LiteralPath $src)) { Done iis skipped '' 'IIS not installed'; return }
    $d = Jp $B 'iis\config'
    $r = Copy-Tree $src $d
    if ($r -ne 'ok') { Done iis failed $d (Short $r); return }
    # Site folders, for the web item.
    $ah = Jp $src 'applicationHost.config'
    if (Test-Path -LiteralPath $ah) {
        foreach ($m in [regex]::Matches([IO.File]::ReadAllText($ah), 'physicalPath="([^"]+)"')) {
            $p = $m.Groups[1].Value -replace '%SystemDrive%', $env:SystemDrive
            if (-not (Test-CcWindows)) { $p = $p -replace '\\', '/' }   # only when the tests run on Linux
            if ($p -and -not ($script:WebRoots -contains $p)) { $script:WebRoots += $p }
        }
    }
    Done iis ok $d ('applicationHost.config and friends; {0} site folders found' -f $script:WebRoots.Count) @(
        '# Stop IIS, copy the settings back, start it:',
        'iisreset /stop',
        ('Copy-Item ' + (Q (Jp $d '*')) + ' ' + (Q $src) + ' -Recurse -Force'),
        'iisreset /start')
}

function I-web {
    if ($NoWebRoots) { Done web skipped '' '-NoWebRoots'; return }
    $roots = @($script:WebRoots)
    $def = Jp $env:SystemDrive 'inetpub\wwwroot'
    if ($env:SystemDrive -and (Test-Path -LiteralPath $def) -and -not ($roots -contains $def)) { $roots += $def }
    if ($roots.Count -eq 0) { Done web skipped '' 'no website folders'; return }
    $d = Sub 'web'; $done = @(); $bad = @(); $restore = @('# Put a site folder back (overwrites changed files; files added since stay - compare first):')
    foreach ($r0 in $roots) {
        if (-not (Test-Path -LiteralPath $r0)) { continue }
        $name = ($r0 -replace '[:\\/ ]+', '_').Trim('_')
        $r = Copy-Tree $r0 (Jp $d $name)
        if ($r -eq 'ok') { $done += $r0; $restore += ('Copy-Item ' + (Q (Jp (Jp $d $name) '*')) + ' ' + (Q $r0) + ' -Recurse -Force') }
        elseif ($r -like 'big:*') { $bad += ('{0} ({1} MB, over -MaxMB)' -f $r0, $r.Substring(4)) }
        else { $bad += ('{0} ({1})' -f $r0, (Short $r)) }
    }
    if ($done.Count -eq 0) { Done web failed $d ('not saved: ' + ($bad -join '; ')); return }
    $det = ('{0} folders' -f $done.Count); if ($bad.Count -gt 0) { $det += '; NOT saved: ' + ($bad -join '; ') }
    Done web ok $d $det $restore
}

function I-dns {
    $dnsDir = Jp $S32 'dns'
    if (-not (Test-CcCommand 'dnscmd.exe') -and -not (Test-Path -LiteralPath $dnsDir)) { Done dns skipped '' 'DNS server not installed'; return }
    $d = Sub 'dns'
    $zones = @()
    if (Test-CcCommand 'dnscmd.exe') {
        foreach ($l in @(Invoke-CcProgram -FilePath 'dnscmd.exe' -Arguments @('/enumzones'))) {
            if ($l -match '^\s+(\S+)\s+(Primary|Secondary|Stub|Forwarder|Cache)') { if ($matches[1] -ne '.' -and $matches[1] -notmatch '^(TrustAnchors|RootDNSServers)$') { $zones += $matches[1] } }
        }
    }
    $saved = @(); $bad = @(); $restore = @('# Put back one zone: copy its file into the DNS folder, then load it.', '# (An AD-integrated zone: delete the broken one first, then add it back as primary from the file and convert it with dnscmd /zoneresettype ZONE /dsprimary.)')
    foreach ($z in $zones) {
        # dnscmd writes the export into %windir%\System32\dns; it is moved out at once.
        $fn = 'ccdc-backup-' + $z + '.dns'
        if (Run 'dnscmd.exe' @('/zoneexport', $z, $fn)) {
            $made = Jp $dnsDir $fn
            if (Test-Path -LiteralPath $made) {
                Move-Item -LiteralPath $made -Destination (Jp $d ($z + '.dns')) -Force
                $saved += $z
                $restore += ('Copy-Item ' + (Q (Jp $d ($z + '.dns'))) + ' ' + (Q (Jp $dnsDir ($z + '.dns'))) + '; dnscmd /zoneadd ' + $z + ' /primary /file ' + $z + '.dns /load')
            } else { $bad += $z }
        } else { $bad += $z }
    }
    # Server settings (forwarders and the like) live in the registry.
    if (Test-CcCommand 'reg.exe') { [void](Run 'reg.exe' @('export', 'HKLM\SYSTEM\CurrentControlSet\Services\DNS', (Jp $d 'dns-server-settings.reg'), '/y')) }
    if (Test-Path -LiteralPath $dnsDir) { [void](Copy-Tree $dnsDir (Jp $d 'dns-folder')) }
    if ($saved.Count -eq 0 -and $zones.Count -gt 0) { Done dns failed $d ('no zone exported: ' + ($bad -join ', ')); return }
    $det = ('{0} zones: {1}' -f $saved.Count, ($saved -join ', ')); if ($bad.Count -gt 0) { $det += '; FAILED: ' + ($bad -join ', ') }
    Done dns ok $d $det $restore
}

function I-dhcp {
    $dhcpDir = Jp $S32 'dhcp'
    if (-not (Test-Path -LiteralPath $dhcpDir)) { Done dhcp skipped '' 'DHCP server not installed'; return }
    $d = Sub 'dhcp'
    # Export-DhcpServer (Server 2012 and later) reads the settings while the
    # service keeps answering clients; netsh is the fallback for older servers.
    if (Test-CcCommand 'Export-DhcpServer') {
        $x = Jp $d 'dhcp-export.xml'
        try { Export-DhcpServer -File $x -Leases -Force -ErrorAction Stop }  # ps2-ok (only where the cmdlet exists)
        catch { Done dhcp failed $d (Short $_.Exception.Message); return }
        Done dhcp ok $d 'scopes, options, reservations, leases' @('# Import into the DHCP server (it keeps its own backup of the current settings in the -BackupPath folder):', ('Import-DhcpServer -File ' + (Q $x) + ' -BackupPath ' + (Q (Jp $d 'before-import')) + ' -Leases -Force'))
        return
    }
    $f = Jp $d 'dhcp-export.txt'
    if (-not (Run 'netsh.exe' @('dhcp', 'server', 'export', $f, 'all')) -or -not (Test-Path -LiteralPath $f)) { Done dhcp failed $d (Short $script:LastOut); return }
    Done dhcp ok $d 'scopes, options, reservations, leases' @('# Import into the DHCP server (stop and restart the DHCP service around it if it complains):', ('netsh dhcp server import ' + (Q $f) + ' all'))
}

$IsDC = $os.IsDC -or (Test-Path -LiteralPath (Jp $Win 'SYSVOL'))
function I-gpo {
    if (-not $IsDC) { Done gpo skipped '' 'not a domain controller'; return }
    $d = Sub 'gpo'
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        $all = @(Backup-GPO -All -Path $d -ErrorAction Stop)
        $rep = Jp $d 'gpo-report.html'
        try { Get-GPOReport -All -ReportType Html -Path $rep -ErrorAction Stop } catch { }
    } catch { Done gpo failed $d (Short $_.Exception.Message); return }
    Done gpo ok $d ('{0} Group Policy objects' -f $all.Count) @(
        '# Put back one GPO as it was (by name), or all of them:',
        ('Restore-GPO -Name "GPO NAME" -Path ' + (Q $d)),
        ('Restore-GPO -All -Domain $env:USERDNSDOMAIN -Path ' + (Q $d)))
}

function I-sysvol {
    $src = Jp $Win 'SYSVOL\domain'
    if (-not (Test-Path -LiteralPath $src)) { $src = Jp $Win 'SYSVOL\sysvol' }
    if (-not $IsDC -or -not (Test-Path -LiteralPath $src)) { Done sysvol skipped '' 'not a domain controller'; return }
    $d = Jp $B 'sysvol'
    $r = Copy-Tree $src $d
    if ($r -like 'big:*') { Done sysvol failed $d ('{0} MB, over -MaxMB' -f $r.Substring(4)); return }
    if ($r -ne 'ok') { Done sysvol failed $d (Short $r); return }
    Done sysvol ok $d 'logon scripts and policy files' @('# Prefer Restore-GPO for policies.  For a logon script the red team changed, copy that one file back from:', ('#   ' + $d + '\scripts'))
}

function I-ad {
    if (-not $IsDC) { Done ad skipped '' 'not a domain controller'; return }
    $d = Sub 'ad'
    $n = 0
    try {
        $root = [ADSI]'LDAP://RootDSE'
        $base = [string]$root.defaultNamingContext
        foreach ($kind in @(@('users', '(&(objectCategory=person)(objectClass=user))', @('samaccountname', 'distinguishedname', 'useraccountcontrol', 'memberof', 'admincount', 'description', 'serviceprincipalname')),
                            @('groups', '(objectClass=group)', @('samaccountname', 'distinguishedname', 'member', 'admincount')),
                            @('computers', '(objectClass=computer)', @('samaccountname', 'distinguishedname', 'operatingsystem', 'useraccountcontrol')),
                            @('ous', '(objectClass=organizationalUnit)', @('name', 'distinguishedname', 'gplink')))) {
            $s = New-Object DirectoryServices.DirectorySearcher([ADSI]('LDAP://' + $base), $kind[1])
            $s.PageSize = 1000
            foreach ($p in $kind[2]) { [void]$s.PropertiesToLoad.Add($p) }
            $lines = @((($kind[2] | ForEach-Object { '"' + $_ + '"' }) -join ','))
            foreach ($r in @($s.FindAll())) {
                $vals = @()
                foreach ($p in $kind[2]) { $v = (@($r.Properties[$p]) | ForEach-Object { [string]$_ }) -join '; '; if ($p -eq 'description' -and $v -match '(?i)(pass(word)?|pwd|pw)\s*[:=]') { $v = '(hidden: password-like text)' }; $vals += ('"' + $v.Replace('"', '""') + '"') }
                $lines += ($vals -join ','); $n++
            }
            [IO.File]::WriteAllLines((Jp $d ($kind[0] + '.csv')), [string[]]$lines)
        }
    } catch { Done ad failed $d (Short $_.Exception.Message); return }
    # The Recycle Bin decides whether a deleted user can be brought back.
    $rb = 'unknown'
    try {
        $cfg = [string]$root.configurationNamingContext
        $o = [ADSI]('LDAP://CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,' + $cfg)
        if (@($o.Properties['msDS-EnabledFeatureBL']).Count -gt 0) { $rb = 'on' } else { $rb = 'OFF' }
    } catch { }
    Add-CcFlag -Severity LOW -Section ad -Item 'AD Recycle Bin' -Detail ("AD Recycle Bin is $rb")
    $restore = @('# Lists for comparison.  A deleted user can only come back through the AD Recycle Bin', ("# (now: $rb).  Turning it on CANNOT be undone; do it early if your team agrees:"),
        '#   Enable-ADOptionalFeature "Recycle Bin Feature" -Scope ForestOrConfigurationSet -Target $env:USERDNSDOMAIN',
        '# Then bring a user back:  Get-ADObject -Filter "samaccountname -eq ''NAME''" -IncludeDeletedObjects | Restore-ADObject')
    Done ad ok $d ("$n objects listed; AD Recycle Bin $rb") $restore
}

function I-addb {
    if (-not $AdDatabase) { Done addb skipped '' 'not asked for (-AdDatabase): it would hold every password hash'; return }
    if (-not $IsDC) { Done addb skipped '' 'not a domain controller'; return }
    $d = Jp $B 'ad-database'
    # ntdsutil reads each argument as one command line; a space in the path
    # would split it.
    if ($d.Contains(' ')) { Done addb failed '' "the output path has a space in it ($d); use -Out C:\ccdc-out"; return }
    if (-not (Run 'ntdsutil.exe' @('activate instance ntds', 'ifm', ('create sysvol full ' + $d), 'quit', 'quit'))) { Done addb failed $d (Short $script:LastOut); return }
    Add-CcFlag -Severity HIGH -Section addb -Item $d -Detail 'this folder holds the AD database with every password hash: copy it off the box with -CopyTo and delete it here'
    Done addb ok $d 'AD database and SYSVOL (install-from-media copy). HOLDS EVERY PASSWORD HASH' @('# Used for an authoritative restore or to build a new DC from media (dcpromo /ReplicaOrNewDomain ...).', '# Do not keep this folder on the DC: delete it after copying it off the box.')
}

function I-paths {
    if ($Path.Count -eq 0) { Done paths skipped '' 'no -Path given'; return }
    $d = Sub 'paths'; $done = @(); $bad = @(); $restore = @()
    foreach ($p in $Path) {
        if (-not (Test-Path -LiteralPath $p)) { $bad += "$p (not found)"; continue }
        $full = Resolve-CcPath $p
        $name = ($full -replace '[:\\/ ]+', '_').Trim('_')
        $r = Copy-Tree $full (Jp $d $name)
        if ($r -eq 'ok') { $done += $full; $restore += ('Copy-Item ' + (Q (Jp $d $name)) + ' ' + (Q $full) + ' -Recurse -Force') }
        elseif ($r -like 'big:*') { $bad += ('{0} ({1} MB, over -MaxMB)' -f $full, $r.Substring(4)) }
        else { $bad += ('{0} ({1})' -f $full, (Short $r)) }
    }
    if ($done.Count -eq 0) { Done paths failed $d ('not saved: ' + ($bad -join '; ')); return }
    $det = ('{0} saved' -f $done.Count); if ($bad.Count -gt 0) { $det += '; NOT saved: ' + ($bad -join '; ') }
    Done paths ok $d $det $restore
}

# ---- Run ----------------------------------------------------------------------
foreach ($i in $AllItems) {
    if (-not (Want $i)) { continue }
    try { & ('I-' + $i) }
    catch { Done $i failed '' ('stopped: ' + (Short $_.Exception.Message)) }
}

# RESTORE.txt, hashes, summary.
$rf = Jp $B 'RESTORE.txt'
$head = @('WN-35 backup of ' + $Cc.Host + ', ' + [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm 'UTC'"),
          'Run these in an elevated PowerShell window, one item at a time, and check the',
          'service still works after each.  Paths are where the backup was made; if you',
          'copied it elsewhere, change the folder at the start of each path.')
[IO.File]::WriteAllLines($rf, [string[]]($head + $script:Restore))

$sums = Jp $B 'SHA256SUMS.txt'
$hl = @()
$bl = $B.Length + 1
foreach ($f in @(Get-ChildItem -LiteralPath $B -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer -and $_.Name -ne 'SHA256SUMS.txt' })) {
    $h = Get-CcSha256 -Path $f.FullName
    if ($h) { $hl += ($h + '  ' + $f.FullName.Substring($bl)) }
}
[IO.File]::WriteAllLines($sums, [string[]]$hl)

$total = [int]((Size $B) / 1MB)
$sum = @()
$sum += ('WN-35 Windows backup  {0}' -f [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm 'UTC'"))
$sum += ('Host: {0}  {1}{2}' -f $Cc.Host, $os.Caption, $(if ($IsDC) { '  (domain controller)' } else { '' }))
$sum += ''
$sum += $script:Lines
$sum += ''
$sum += ('{0} saved, {1} failed, {2} skipped; {3} files, {4} MB' -f $script:Count.ok, $script:Count.failed, $script:Count.skipped, $hl.Count, $total)
$sum += ('Restore commands: ' + $rf)

# Copy off the box.
if ($CopyTo) {
    $dest = Jp $CopyTo (Split-Path -Leaf $B)
    try {
        Copy-Item -LiteralPath $B -Destination $dest -Recurse -Force -ErrorAction Stop
        $n2 = @(Get-ChildItem -LiteralPath $dest -Recurse -Force | Where-Object { -not $_.PSIsContainer }).Count
        if ($n2 -lt $hl.Count + 1) { $sum += ('COPY INCOMPLETE: {0} of {1} files reached {2}' -f $n2, ($hl.Count + 1), $dest); $script:Count.failed++ }
        else { $sum += ('Copied to: ' + $dest) }
    } catch {
        $sum += ('COPY FAILED to {0}: {1}' -f $CopyTo, $_.Exception.Message)
        $script:Count.failed++
    }
} else {
    $sum += 'Not copied off the box: use -CopyTo \\server\share (a red team with admin rights can delete it here).'
    Write-CcLog -Level WARN -Message 'not copied off the box: use -CopyTo \\server\share (a red team with admin rights can delete it here)'
}
if ($AdDatabase -and $script:Count.ok -gt 0 -and (Test-Path -LiteralPath (Jp $B 'ad-database'))) { $sum += 'WARNING: ad-database\ holds every domain password hash. Copy it off the box, then delete it here.' }

[IO.File]::WriteAllLines((Jp $B 'summary.txt'), [string[]]$sum)
if ($CopyTo -and (Test-Path -LiteralPath (Jp $CopyTo (Split-Path -Leaf $B)))) { Copy-Item -LiteralPath (Jp $B 'summary.txt') -Destination (Jp (Jp $CopyTo (Split-Path -Leaf $B)) 'summary.txt') -Force -ErrorAction SilentlyContinue }
if (-not $Quiet) { foreach ($l in $sum) { Write-Host $l } }
Write-Host ('All results: ' + $B)
if ($script:Count.failed -gt 0) { Complete-Cc -ExitCode 5 }
Complete-Cc
