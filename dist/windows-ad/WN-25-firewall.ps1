# =============================================================================
# ID:       WN-25
# NAME:     Windows firewall
# ROLE:     Windows / AD  (wave 2, first 15 minutes)
# KIND:     changes - dry run unless -Apply; rolls itself back unless confirmed
# VERSION:  1.0.0
#
# PURPOSE
#   Turns the Windows firewall on for every profile with inbound blocked by
#   default, and allows in only:
#     - the ports on the protected list and -Allow (always: scored services)
#     - the ports that are listening now, minus loopback-only ones, known
#       backdoor ports, ports above 49151, -Exclude, and ports whose program
#       is a shell, netcat or something in a temp folder
#     - everything from the scoring engine and admin addresses (protected
#       list "host" entries and -AdminFrom)
#     - ping (ICMP echo), unless -NoPing
#     - on a domain controller, the ports Active Directory needs (DNS,
#       Kerberos, LDAP, GC, SMB, RPC, NTP, password change)
#   Existing rules that undo all of this - an enabled inbound rule that allows
#   everything, a rule for a shell or a program in a temp folder, a rule
#   opening a backdoor port - are turned off.  -Strict turns off EVERY
#   inbound allow rule that is not one of ours (except Active Directory's on
#   a DC).  Dropped connections are logged to Windows' firewall log.
#
#   SAFETY: the whole firewall is exported first.  A rollback task (SYSTEM,
#   runs even if this window or RDP session is gone) restores that export
#   after -ConfirmMinutes (default 5) unless someone confirms from a NEW
#   connection with keep-firewall.ps1 - proof the change did not lock the team
#   out.  -Undo puts the old firewall back at any time.
#
# USAGE
#   powershell -NoProfile -ExecutionPolicy Bypass -File WN-25-firewall.ps1 -Out C:\bt-out                    dry run: shows the plan
#   powershell ... WN-25-firewall.ps1 -Out C:\bt-out -Apply -AdminFrom 10.0.0.5
#     then, from a NEW RDP/remote session within 5 minutes:
#   powershell ... <run folder>\keep-firewall.ps1
#   powershell ... WN-25-firewall.ps1 -Out C:\bt-out -Undo latest -Apply     put the old firewall back
#   Run in an elevated Windows PowerShell (powershell.exe) window.
#
# OPTIONS
#   -Allow a,b         always allow these ports: 80/tcp, 53/udp, 5000-5100/tcp
#                      (no /proto means tcp)
#   -Exclude a,b       never open these ports, even if something listens on
#                      them (the protected list still wins, with a warning)
#   -AdminFrom a,b     allow everything from these addresses or networks
#                      (10.0.0.5, 10.0.0.0/24) as well as protected hosts
#   -Strict            turn off every inbound allow rule that is not ours
#   -NoPing            do not allow ICMP echo
#   -NoLog             do not turn on the dropped-connection log
#   -ConfirmMinutes N  rollback timer (default 5, 2..60)
#   -NoTimer           no rollback timer (only when you are at the console)
#   -Undo RUN          put back the firewall from before a run: "latest" or
#                      a run folder.  Dry run unless -Apply
#   -Remove            remove only the rules this script added (group "BT")
#   Common options (-Apply, -Out, -Protected, -NoProtected, -Quiet,
#   -DebugLog) come from the library.
#
# OUTPUTS  (under -Out, in WN-25_<host>_<UTC time>\)
#   plan.csv              every allow rule it adds and why
#   disabled.csv          every existing rule it turns off and why
#   not-allowed.csv       listening ports it did NOT open and why
#   firewall-before.wfw   the whole firewall before the change (netsh export)
#   keep-firewall.ps1     run it from a NEW connection to keep the change
#   rollback.ps1          what the timer runs; you can run it too
#   summary.txt           the plan and the result
#   Dropped connections: %windir%\System32\LogFiles\Firewall\pfirewall.log
#
# WHAT IT CHANGES  (only with -Apply)
#   Firewall profiles (on, block inbound, allow outbound, logging), adds
#   rules in the group "BT", turns off the existing rules listed in
#   disabled.csv, and creates the scheduled task "BT-WN25-rollback" until
#   the change is kept or rolled back.  Outbound traffic is not limited.
#
# DEPENDS ON
#   The firewall COM object (HNetCfg.FwPolicy2), netsh advfirewall, netstat,
#   WMI (Win32_Process), schtasks - Windows 7 / Server 2008 R2 and later.
#   $env:BT_WN25_FAKE names a folder of stand-in state for the tests: then
#   nothing on the machine is read or changed.
#
# TESTED ON
#   PowerShell 7 on Linux against stand-in state (tests/wn25.Tests.ps1).
#   NOT yet run on real Windows: run it on a throwaway VM first.
#
# KNOWN LIMITS / WHAT TO WATCH FOR
#   - A scored service that is DOWN when this runs, and is not on the
#     protected list or -Allow, is not opened.  Fill in the protected list.
#   - Group Policy firewall rules and settings win over local ones; a domain
#     GPO can put things back at the next refresh.
#   - A rerun removes rules of ours that the new plan does not have, so a
#     port added to -Exclude (or a listener that stopped) is closed again.
#   - Discovery UDP (1900, 3702, 5353, 5355) is not opened; -Strict keeps
#     Windows' core networking rules (DHCP, IPv6 neighbour discovery).
#   - Only inbound is limited.  IPv6 is treated like IPv4 (the same rules).
#   - netstat and WMI see what Windows reports; a rootkit can hide a listener.
#
# DEBUGGING
#   -DebugLog          every listener and rule and the decision about it
#   plan.csv / disabled.csv / not-allowed.csv   the reasons, one per line
#   schtasks /query /tn BT-WN25-rollback      is a rollback still waiting?
# =============================================================================
param(
    [switch]$Apply, [string]$Out, [string]$Protected, [switch]$NoProtected,
    [switch]$ForceScored, [switch]$Quiet, [switch]$DebugLog,
    [string[]]$Allow = @(),
    [string[]]$Exclude = @(),
    [string[]]$AdminFrom = @(),
    [switch]$Strict,
    [switch]$NoPing,
    [switch]$NoLog,
    [int]$ConfirmMinutes = 5,
    [switch]$NoTimer,
    [string]$Undo = '',
    [switch]$Remove,
    [switch]$Help
)

if ($Help) {
    Write-Host 'WN-25 Windows firewall - default-deny inbound, scored ports open, rollback timer'
    Write-Host '  -Allow 80/tcp,53/udp   -Exclude 8080/tcp   -AdminFrom 10.0.0.5,10.0.0.0/24'
    Write-Host '  -Strict  -NoPing  -NoLog  -ConfirmMinutes N  -NoTimer'
    Write-Host '  -Undo latest|RUNFOLDER   -Remove (only the rules this script added)'
    Write-Host '  -Apply -Out DIR -Protected FILE -NoProtected -Quiet -DebugLog'
    exit 0
}

# >>> BT-LIB  (lib/lib.ps1 0.6.0 pasted in by tools/build.sh - edit lib/lib.ps1, not this copy)
# =============================================================================
# ID:       LB-02
# NAME:     PowerShell library (lib.ps1)
# ROLE:     Automation  (wave 0, foundation)
# VERSION:  0.6.0
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

$script:CcLibVersion = '0.6.0'

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
    exit $ExitCode
}
# <<< BT-LIB

function Lc($s) { if ($null -eq $s) { return '' }; return ([string]$s).ToLower() }
function Nz($s) { if ($null -eq $s) { return '' }; return [string]$s }
function Q([string]$s) { return "'" + $s.Replace("'", "''") + "'" }

# ---- Options ----------------------------------------------------------------
# Lists split inline (not by a function): Windows PowerShell 5.1 turns an
# empty list returned from a function into $null.
$Allow = @(@($Allow) | Where-Object { $_ } | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$Exclude = @(@($Exclude) | Where-Object { $_ } | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$AdminFrom = @(@($AdminFrom) | Where-Object { $_ } | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

# Parse-Port "80/tcp" -> @{ Proto = 'TCP'; Ports = '80' } or $null.
function Parse-Port([string]$s) {
    $m = [regex]::Match($s.Trim(), '^(\d{1,5})(-(\d{1,5}))?(/(tcp|udp))?$', 'IgnoreCase')
    if (-not $m.Success) { return $null }
    $a = [int]$m.Groups[1].Value; $b = $a
    if ($m.Groups[3].Success) { $b = [int]$m.Groups[3].Value }
    if ($a -lt 1 -or $b -gt 65535 -or $b -lt $a) { return $null }
    $proto = 'TCP'; if ($m.Groups[5].Success) { $proto = $m.Groups[5].Value.ToUpper() }
    $ports = [string]$a; if ($b -ne $a) { $ports = "$a-$b" }
    return @{ Proto = $proto; Ports = $ports; Lo = $a; Hi = $b }
}
foreach ($p in @($Allow + $Exclude)) { if ($null -eq (Parse-Port $p)) { Write-Host "not a port: '$p' (use 80, 80/tcp, 53/udp or 5000-5100/tcp)"; exit 2 } }
function Valid-Addr([string]$a) {
    if ($a -match '^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(/(\d{1,2}))?$') {
        for ($i = 1; $i -le 4; $i++) { if ([int]$matches[$i] -gt 255) { return $false } }
        if ($matches[6] -and [int]$matches[6] -gt 32) { return $false }
        return $true
    }
    return ($a -match '^[0-9a-fA-F:]+(/\d{1,3})?$' -and $a.Contains(':'))
}
foreach ($a in $AdminFrom) { if (-not (Valid-Addr $a)) { Write-Host "-AdminFrom: not an address or network: '$a'"; exit 2 } }
if ($ConfirmMinutes -lt 2 -or $ConfirmMinutes -gt 60) { Write-Host '-ConfirmMinutes must be 2..60'; exit 2 }
if ($Undo -and $Remove) { Write-Host 'use -Undo or -Remove, not both'; exit 2 }

# ---- Start ------------------------------------------------------------------
Initialize-Cc -Id 'WN-25' -Name 'Windows firewall' -Kind changes -Bound $PSBoundParameters
$Fake = $env:BT_WN25_FAKE
if ($Fake) { Write-CcLog -Level WARN -Message "TEST MODE: stand-in state from $Fake; nothing on this machine is read or changed" }
else {
    if (-not (Test-CcCommand 'Get-WmiObject')) { Stop-Cc -Code 3 -Message 'run this with Windows PowerShell (powershell.exe), not PowerShell 7 (pwsh)' }
    if ($Cc.Apply) { Assert-CcAdmin }
}
$TaskName = 'BT-WN25-rollback'
$Group = 'BT'

# =============================================================================
# State providers: every read and write of the firewall goes through these,
# so the tests can use stand-in state ($env:BT_WN25_FAKE).
# =============================================================================
function FP([string]$n) { return [IO.Path]::Combine($Fake, $n) }
function F-Read([string]$n) { $p = FP $n; if (-not (Test-Path -LiteralPath $p)) { return @() }; return @([IO.File]::ReadAllLines($p) | ConvertFrom-Csv) }
function F-Write([string]$n, [string[]]$h, $rows) {
    $l = @(($h | ForEach-Object { '"' + $_ + '"' }) -join ',')
    foreach ($r in @($rows)) { $l += (($h | ForEach-Object { '"' + (Nz $r.$_).Replace('"', '""') + '"' }) -join ',') }
    [IO.File]::WriteAllLines((FP $n), [string[]]$l)
}
$RuleCols = @('name', 'enabled', 'protocol', 'lports', 'raddr', 'app', 'svc', 'group', 'pkg', 'laddr', 'iface', 'icmp')
$script:Fw = $null
function Fw { if ($null -eq $script:Fw) { $script:Fw = New-Object -ComObject HNetCfg.FwPolicy2 }; return $script:Fw }

# Get-Profiles -> rows: Name, On (bool), BlockIn (bool)
function Get-Profiles {
    if ($Fake) { return @(F-Read 'profiles.csv' | ForEach-Object { New-Object PSObject -Property @{ Name = $_.name; On = ($_.on -eq 'True'); BlockIn = ($_.blockin -eq 'True') } }) }
    $out = @()
    foreach ($p in @(@('Domain', 1), @('Private', 2), @('Public', 4))) {
        $out += New-Object PSObject -Property @{ Name = $p[0]; On = [bool](Fw).FirewallEnabled($p[1]); BlockIn = ((Fw).DefaultInboundAction($p[1]) -eq 0) }
    }
    return $out
}
function Set-Profiles {
    if ($Fake) { F-Write 'profiles.csv' @('name', 'on', 'blockin') @(@('Domain', 'Private', 'Public') | ForEach-Object { New-Object PSObject -Property @{ name = $_; on = 'True'; blockin = 'True' } }); return }
    foreach ($a in @(@('allprofiles', 'state', 'on'), @('allprofiles', 'firewallpolicy', 'blockinbound,allowoutbound'))) {
        [void](Invoke-CcProgram -FilePath 'netsh.exe' -Arguments (@('advfirewall', 'set') + $a))
        if ($LASTEXITCODE -ne 0) { throw ('netsh advfirewall set ' + ($a -join ' ') + " failed (exit $LASTEXITCODE)") }
    }
}
function Set-Logging {
    if ($Fake) { [IO.File]::WriteAllText((FP 'logging.txt'), 'droppedconnections enable'); return }
    foreach ($a in @(@('logging', 'droppedconnections', 'enable'), @('logging', 'maxfilesize', '32767'))) {
        [void](Invoke-CcProgram -FilePath 'netsh.exe' -Arguments (@('advfirewall', 'set', 'allprofiles') + $a))
        if ($LASTEXITCODE -ne 0) { throw "netsh logging failed (exit $LASTEXITCODE)" }
    }
}
# Get-InRules -> enabled-or-not inbound ALLOW rules as rows with $RuleCols.
function Get-InRules {
    if ($Fake) { return @(F-Read 'rules.csv') }
    $out = @()
    foreach ($r in @((Fw).Rules)) {
        if ($r.Direction -ne 1 -or $r.Action -ne 1) { continue }
        $pkg = ''; try { $pkg = [string]$r.LocalAppPackageId } catch { }
        $icmp = ''; try { $icmp = [string]$r.IcmpTypesAndCodes } catch { }
        $out += New-Object PSObject -Property @{ name = [string]$r.Name; enabled = [string][bool]$r.Enabled; protocol = [string]$r.Protocol; lports = [string]$r.LocalPorts
            raddr = [string]$r.RemoteAddresses; app = [string]$r.ApplicationName; svc = [string]$r.ServiceName; group = [string]$r.Grouping; pkg = $pkg
            laddr = [string]$r.LocalAddresses; iface = [string]$r.InterfaceTypes; icmp = $icmp }
    }
    return $out
}
# Key of a rule: what makes it this rule (names repeat).
function RKey($r) { return ((@($r.name, $r.protocol, $r.lports, $r.raddr, $r.app, $r.svc, $r.group) | ForEach-Object { Lc $_ }) -join '|') }
function Disable-Rule($x) {
    if ($Fake) {
        $rows = @(F-Read 'rules.csv'); foreach ($r in $rows) { if ((RKey $r) -eq (RKey $x)) { $r.enabled = 'False' } }
        F-Write 'rules.csv' $RuleCols $rows; return
    }
    $n = 0
    foreach ($r in @((Fw).Rules)) {
        if ($r.Direction -ne 1 -or $r.Action -ne 1) { continue }
        $k = ((@($r.Name, $r.Protocol, $r.LocalPorts, $r.RemoteAddresses, $r.ApplicationName, $r.ServiceName, $r.Grouping) | ForEach-Object { Lc $_ }) -join '|')
        if ($k -eq (RKey $x)) { $r.Enabled = $false; $n++ }
    }
    if ($n -eq 0) { throw 'rule not found any more' }
}
# Norm-Addrs "10.0.0.5,10.0.0.0/24" -> "10.0.0.0/255.255.255.0,10.0.0.5/255.255.255.255"
#   The firewall reports addresses with dotted masks; ours are compared in
#   the same form, sorted.  '' and '*' mean any.
function Norm-Addrs([string]$list) {
    if ($list -eq '' -or $list -eq '*') { return '*' }
    $o = @()
    foreach ($x in @($list -split ',')) {
        $x = $x.Trim()
        if ($x -match '^(\d+\.\d+\.\d+\.\d+)(/(\d+))?$') {
            $bits = 32; if ($matches[3]) { $bits = [int]$matches[3] }
            if ($x -match '/\d+\.') { $o += $x; continue }
            $m = @(); for ($i = 0; $i -lt 4; $i++) { $n = [Math]::Min(8, [Math]::Max(0, $bits - 8 * $i)); $m += (256 - [Math]::Pow(2, 8 - $n)) }
            $o += ($matches[1] + '/' + ($m -join '.'))
        } else { $o += $x.ToLower() }
    }
    return ((@($o) | Sort-Object) -join ',')
}
# Has-Rule NAME -> $true when a rule of ours with this name exists (a second
# run must not add every rule again).
function Has-Rule([string]$name) {
    if ($Fake) { return (@(F-Read 'rules.csv' | Where-Object { $_.group -eq $Group -and $_.name -eq $name }).Count -gt 0) }
    return (@(@((Fw).Rules) | Where-Object { $_.Grouping -eq $Group -and $_.Name -eq $name }).Count -gt 0)
}
# Add-Rule NAME PROTO PORTS RADDR -> PROTO TCP|UDP|ANY|ICMP
function Add-Rule([string]$name, [string]$proto, [string]$ports, [string]$raddr) {
    if ($Fake) {
        $rows = @(F-Read 'rules.csv')
        $rows += New-Object PSObject -Property @{ name = $name; enabled = 'True'; protocol = $proto; lports = $ports; raddr = $raddr; app = ''; svc = ''; group = $Group; pkg = ''; laddr = ''; iface = ''; icmp = '' }
        F-Write 'rules.csv' $RuleCols $rows; return
    }
    $r = New-Object -ComObject HNetCfg.FWRule
    $r.Name = $name
    $r.Description = 'Added by WN-25 (the kit). Remove with WN-25 -Remove.'
    $r.Grouping = $Group
    $r.Direction = 1; $r.Action = 1; $r.Profiles = 2147483647
    switch ($proto) {
        'TCP' { $r.Protocol = 6; $r.LocalPorts = $ports }
        'UDP' { $r.Protocol = 17; $r.LocalPorts = $ports }
        'ICMP' { $r.Protocol = 1; $r.IcmpTypesAndCodes = '8:*' }
        default { $r.Protocol = 256 }
    }
    if ($raddr) { $r.RemoteAddresses = $raddr }
    $r.Enabled = $true
    (Fw).Rules.Add($r)
}
function Remove-Ours {
    if ($Fake) { $all = @(F-Read 'rules.csv'); $keep = @($all | Where-Object { $_.group -ne $Group }); F-Write 'rules.csv' $RuleCols $keep; return ($all.Count - $keep.Count) }
    $n = 0
    $names = @(@((Fw).Rules) | Where-Object { $_.Grouping -eq $Group } | ForEach-Object { $_.Name } | Select-Object -Unique)
    foreach ($nm in $names) { while (@(@((Fw).Rules) | Where-Object { $_.Grouping -eq $Group -and $_.Name -eq $nm }).Count -gt 0) { (Fw).Rules.Remove($nm); $n++ } }
    return $n
}
function Export-Fw([string]$file) {
    if ($Fake) {
        if ($env:BT_WN25_FAIL -eq 'export') { throw 'access denied (test)' }
        $d = $file + '.d'; New-Item -ItemType Directory -Path $d -Force | Out-Null
        foreach ($n in @('profiles.csv', 'rules.csv', 'logging.txt')) { if (Test-Path -LiteralPath (FP $n)) { Copy-Item -LiteralPath (FP $n) -Destination (Join-Path $d $n) -Force } }
        [IO.File]::WriteAllText($file, 'fake export'); return
    }
    [void](Invoke-CcProgram -FilePath 'netsh.exe' -Arguments @('advfirewall', 'export', $file))
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $file)) { throw "netsh advfirewall export failed (exit $LASTEXITCODE)" }
}
function Import-Fw([string]$file) {
    if ($Fake) {
        $d = $file + '.d'
        if (-not (Test-Path -LiteralPath (Join-Path $d 'logging.txt'))) { Remove-Item -LiteralPath (FP 'logging.txt') -Force -ErrorAction SilentlyContinue }
        foreach ($f in @(Get-ChildItem -LiteralPath $d)) { Copy-Item -LiteralPath $f.FullName -Destination (FP $f.Name) -Force }
        return
    }
    [void](Invoke-CcProgram -FilePath 'netsh.exe' -Arguments @('advfirewall', 'import', $file))
    if ($LASTEXITCODE -ne 0) { throw "netsh advfirewall import failed (exit $LASTEXITCODE)" }
}
# Listeners: netstat -ano parsed, with each process's name and program.
function Get-Listeners {
    $lines = @(); $procs = @{}
    if ($Fake) {
        $p = FP 'netstat.txt'; if (Test-Path -LiteralPath $p) { $lines = @([IO.File]::ReadAllLines($p)) }
        foreach ($r in @(F-Read 'processes.csv')) { $procs[$r.pid] = $r }
    } else {
        $lines = @(Invoke-CcProgram -FilePath 'netstat.exe' -Arguments @('-ano'))
        foreach ($p in @(Get-WmiObject -Class Win32_Process -ErrorAction SilentlyContinue)) { $procs[[string]$p.ProcessId] = New-Object PSObject -Property @{ pid = [string]$p.ProcessId; name = [string]$p.Name; path = [string]$p.ExecutablePath } }
    }
    $out = @(); $seen = @{}
    foreach ($l in $lines) {
        $f = @($l.Trim() -split '\s+')
        if ($f.Count -lt 4) { continue }
        $proto = $f[0].ToUpper()
        if ($proto -eq 'TCP' -and $f.Count -ge 5) { $procId = $f[4]; $raddr = $f[2] }
        elseif ($proto -eq 'UDP') { $procId = $f[$f.Count - 1]; $raddr = '*:*' }
        else { continue }
        $ri = $raddr.LastIndexOf(':'); if ($proto -eq 'TCP' -and $raddr.Substring($ri + 1) -ne '0') { continue }
        $li = $f[1].LastIndexOf(':'); if ($li -lt 0) { continue }
        $addr = $f[1].Substring(0, $li).Trim('[', ']'); $port = $f[1].Substring($li + 1)
        $k = "$proto|$port|$addr"
        if ($seen.ContainsKey($k)) { continue }; $seen[$k] = 1
        $pr = $procs[$procId]
        $name = ''; $path = ''; if ($pr) { $name = $pr.name; $path = $pr.path }; if ($procId -eq '4') { $name = 'System' }
        $out += New-Object PSObject -Property @{ Proto = $proto; Addr = $addr; Port = [int]$port; Pid = $procId; Name = $name; Path = $path }
    }
    return $out
}
# Rollback task: runs as SYSTEM at a fixed time, so it fires even if this
# session is gone.  The trigger time is ISO 8601 in XML, so it does not
# depend on the machine's date format.
function Task-Exists {
    if ($Fake) { return (Test-Path -LiteralPath (FP 'task.txt')) }
    [void](Invoke-CcProgram -FilePath 'schtasks.exe' -Arguments @('/query', '/tn', $TaskName))
    $e = $LASTEXITCODE; $global:LASTEXITCODE = 0
    return ($e -eq 0)
}
function Task-Delete {
    if ($Fake) { Remove-Item -LiteralPath (FP 'task.txt') -Force -ErrorAction SilentlyContinue; return }
    [void](Invoke-CcProgram -FilePath 'schtasks.exe' -Arguments @('/delete', '/tn', $TaskName, '/f'))
    $global:LASTEXITCODE = 0
}
# Pending-Run -> the run folder whose change is neither kept nor rolled back
# (has rollback.ps1, no KEPT, no ROLLED_BACK), or ''.
function Pending-Run {
    foreach ($d in @(Get-ChildItem -LiteralPath $Cc.Out -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer -and $_.Name -like ('WN-25_' + $Cc.Host + '_*') } | Sort-Object Name -Descending)) {
        $f = $d.FullName
        if ((Test-Path -LiteralPath (Join-Path $f 'rollback.ps1')) -and -not (Test-Path -LiteralPath (Join-Path $f 'KEPT')) -and -not (Test-Path -LiteralPath (Join-Path $f 'ROLLED_BACK')) -and -not (Test-Path -LiteralPath (Join-Path $f 'UNDONE'))) { return $f }
    }
    return ''
}
function Task-Create([DateTime]$when, [string]$script) {
    if ($Fake) { [IO.File]::WriteAllText((FP 'task.txt'), ($when.ToString('s') + '|' + $script)); return }
    $cmd = 'powershell.exe'
    $arg = '-NoProfile -ExecutionPolicy Bypass -File "' + $script + '"'
    $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>BT WN-25: put the old firewall back unless the change was kept</Description></RegistrationInfo>
  <Triggers><TimeTrigger><StartBoundary>$($when.ToString('s'))</StartBoundary><Enabled>true</Enabled></TimeTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><ExecutionTimeLimit>PT10M</ExecutionTimeLimit><Enabled>true</Enabled></Settings>
  <Actions Context="Author"><Exec><Command>$cmd</Command><Arguments>$([Security.SecurityElement]::Escape($arg))</Arguments></Exec></Actions>
</Task>
"@
    $xf = Join-Path $Cc.RunDir 'rollback-task.xml'
    [IO.File]::WriteAllText($xf, $xml, [Text.Encoding]::Unicode)
    [void](Invoke-CcProgram -FilePath 'schtasks.exe' -Arguments @('/create', '/tn', $TaskName, '/xml', $xf, '/ru', 'SYSTEM', '/f'))
    if ($LASTEXITCODE -ne 0) { throw "schtasks /create failed (exit $LASTEXITCODE)" }
}

# =============================================================================
# -Undo and -Remove
# =============================================================================
function Find-Run([string]$which) {
    if ($which -eq 'latest') {
        $c = @(Get-ChildItem -LiteralPath $Cc.Out -Force | Where-Object { $_.PSIsContainer -and $_.Name -like ('WN-25_' + $Cc.Host + '_*') -and (Test-Path -LiteralPath (Join-Path $_.FullName 'firewall-before.wfw')) } | Sort-Object Name)
        if ($c.Count -eq 0) { Stop-Cc -Code 2 -Message "no WN-25 run with a firewall export in $($Cc.Out)" }
        return $c[-1].FullName
    }
    if (Test-Path -LiteralPath (Join-Path $which 'firewall-before.wfw')) { return (Resolve-CcPath $which) }
    $t = Join-Path $Cc.Out $which
    if (Test-Path -LiteralPath (Join-Path $t 'firewall-before.wfw')) { return $t }
    Stop-Cc -Code 2 -Message "-Undo: $which has no firewall-before.wfw"
}
if ($Undo) {
    $dir = Find-Run $Undo
    $exp = Join-Path $dir 'firewall-before.wfw'
    Write-CcLog -Level INFO -Message "undo: the firewall as it was before $dir"
    $ok = Invoke-CcChange -Description ('put back the whole firewall from ' + $exp) -Action { Import-Fw $exp }
    if ($ok -and $Cc.Apply) {
        if (Task-Exists) { [void](Invoke-CcChange -Description "delete the rollback task $TaskName" -Action { if ($Fake) { Remove-Item -LiteralPath (FP 'task.txt') -Force } else { [void](Invoke-CcProgram -FilePath 'schtasks.exe' -Arguments @('/delete', '/tn', $TaskName, '/f')) } }) }
        [IO.File]::WriteAllText((Join-Path $dir 'UNDONE'), [DateTime]::UtcNow.ToString('o'))
    }
    if (-not $Cc.Apply) { Write-Host 'Dry run: nothing was put back. Add -Apply.' }
    Write-Host ('Undo of: ' + $dir)
    Complete-Cc
}
if ($Remove) {
    $n = 0
    [void](Invoke-CcChange -Description "remove the rules in group $Group (the ones WN-25 added)" -Action { $script:Removed = Remove-Ours })
    if ($Cc.Apply) { Write-Host ('Removed {0} rules in group {1}. Profiles and the rules WN-25 turned off are unchanged (use -Undo for the whole firewall).' -f $script:Removed, $Group) }
    Complete-Cc
}

# =============================================================================
# Plan
# =============================================================================
Use-CcRunDir
$Dir = $Cc.RunDir
if ($Fake) { $IsDC = Test-Path -LiteralPath (FP 'is-dc') } else { $IsDC = (Get-CcOsInfo).IsDC }

$ShellNames = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'nc.exe', 'nc64.exe', 'ncat.exe', 'socat.exe', 'plink.exe', 'chisel.exe', 'ngrok.exe')
$OddRe = '(\\users\\public\\|\\perflogs\\|\\windows\\temp\\|\\temp\\|\\tmp\\|\\appdata\\|\\downloads\\|\\programdata\\[^\\]+\.(exe|dll)|\$recycle\.bin|\\windows\\tasks\\)'
$BadPorts = @(4444, 4445, 1337, 31337, 5555, 6666, 6667, 6697, 9001, 9999, 12345, 54321)
# UDP ports Windows listens on for local discovery (SSDP, WS-Discovery, mDNS,
# LLMNR): not services anyone scores, and LLMNR is a favourite for spoofing.
# Not opened unless the protected list or -Allow names them.
$DiscoveryUdp = @(1900, 3702, 5353, 5355)
# -Strict keeps these: Windows' own networking (DHCP, IPv6 neighbour
# discovery) - turning them off can drop the address when the lease renews,
# long after the rollback timer is gone.
$CoreRe = '(core networking|@firewallapi\.dll,-25000)'

# Protected list: ports and hosts.
$protPorts = @(); $protHosts = @()
[void](Test-CcProtected -Type host -Value 'load')   # reads the list into $Cc.ProtectedRows
foreach ($e in @($Cc.ProtectedRows)) {
    if ($null -eq $e) { continue }
    if ($e[0] -eq 'port') { $pp = Parse-Port $e[1]; if ($pp) { $protPorts += ($pp.Ports + '/' + $pp.Proto.ToLower()) } else { Write-CcLog -Level WARN -Message "protected list: '$($e[1])' is not a port" } }
    if ($e[0] -eq 'host') { if (Valid-Addr $e[1]) { $protHosts += $e[1] } else { Write-CcLog -Level WARN -Message "protected list: host '$($e[1])' is not an address; names are not used by the firewall" } }
}
$admins = @(@($protHosts) + @($AdminFrom) | Select-Object -Unique)

# want: key "ports/proto" -> reason
$want = @{}; $order = @()
function Want([string]$spec, [string]$why) { $pp = Parse-Port $spec; $k = $pp.Ports + '/' + $pp.Proto.ToLower(); if (-not $want.ContainsKey($k)) { $want[$k] = $why; $script:order += $k } else { $want[$k] += '; ' + $why } }
$exL = @($Exclude | ForEach-Object { $pp = Parse-Port $_; $pp.Ports + '/' + $pp.Proto.ToLower() })
foreach ($p in $protPorts) { Want $p 'protected list (scored)'; if ($exL -contains $p) { Write-CcLog -Level WARN -Message "$p is both protected and in -Exclude: the protected list wins, it is opened" } }
foreach ($p in $Allow) { Want $p '-Allow' }
if ($IsDC) {
    foreach ($p in @('53/tcp', '53/udp', '88/tcp', '88/udp', '135/tcp', '389/tcp', '389/udp', '445/tcp', '464/tcp', '464/udp', '636/tcp', '3268-3269/tcp', '123/udp')) { Want $p 'domain controller (Active Directory)' }
}
$notCsv = New-CcCsv -Name 'not-allowed' -Header @('port', 'address', 'process', 'program', 'why')
$listeners = @(Get-Listeners)
foreach ($l in ($listeners | Sort-Object Port)) {
    $k = ('{0}/{1}' -f $l.Port, (Lc $l.Proto))
    $why = ''
    $ln = Lc $l.Name; $lp = Lc $l.Path
    if ($l.Addr -like '127.*' -or $l.Addr -eq '::1') { continue }
    if ($ShellNames -contains $ln) { $why = "$($l.Name) is listening: a shell or tunnel, not a service" }
    elseif ($BadPorts -contains $l.Port) { $why = "port $($l.Port) is a common backdoor port" }
    elseif ($lp -ne '' -and $lp -match $OddRe) { $why = "its program runs from an unusual folder: $($l.Path)" }
    elseif ($l.Proto -eq 'UDP' -and $DiscoveryUdp -contains $l.Port) { $why = 'local network discovery (SSDP/WS-Discovery/mDNS/LLMNR), not a service' }
    elseif ($l.Port -ge 49152) { $why = 'dynamic port (49152 and up): not opened (a DC gets RPC through its own rule)' }
    elseif ($exL -contains $k) { $why = '-Exclude' }
    if ($why) {
        if ($want.ContainsKey($k)) { Write-CcLog -Level WARN -Message "$k is wanted ($($want[$k])) but $why - it is opened because the list says so" }
        else { Add-CcCsvRow -File $notCsv -Values @($k, $l.Addr, $l.Name, $l.Path, $why); Write-CcLog -Level DEBUG -Message "not opening ${k}: $why"; continue }
    }
    $who = $l.Name; if (-not $who) { $who = 'pid ' + $l.Pid }
    Want $k ("listening now: $who")
}

# Existing inbound allow rules: which to turn off.
$rules = @(Get-InRules)
$dcKeep = '(lsass|dns\.exe|dfsrs|ntfrs|ntdsmsg|netlogon|kdc|kerberos|w32time|dfsr|samss|rpcss|ntds|activedirectory)'
$off = @()
foreach ($r in $rules) {
    if ($r.enabled -ne 'True' -or $r.group -eq $Group) { continue }
    $app = Lc $r.app; $leaf = @($app -split '\\')[-1]
    $anyProto = ($r.protocol -eq '256' -or $r.protocol -eq '' -or (Lc $r.protocol) -eq 'any')
    $anyPort = ($r.lports -eq '' -or $r.lports -eq '*')
    $anyAddr = ($r.raddr -eq '' -or $r.raddr -eq '*')
    $limited = ($r.pkg -or ($r.laddr -and $r.laddr -ne '*') -or ($r.iface -and (Lc $r.iface) -ne 'all') -or ($r.svc -and $r.svc -ne '*'))
    $why = ''
    if ($anyProto -and $anyPort -and $anyAddr -and -not $app -and -not $limited) { $why = 'allows every port, protocol and address' }
    elseif ($ShellNames -contains $leaf) { $why = "allows a shell or tunnel in: $($r.app)" }
    elseif ($app -match $OddRe) { $why = "allows a program in an unusual folder: $($r.app)" }
    else { foreach ($bp in $BadPorts) { if (@($r.lports -split ',' | ForEach-Object { $_.Trim() }) -contains [string]$bp) { $why = "opens backdoor port $bp" } } }
    if (-not $why -and $Strict) {
        $core = ((Lc ($r.group + ' ' + $r.name)) -match $CoreRe) -or $r.protocol -eq '58' -or ($r.protocol -eq '17' -and @('68', '546') -contains $r.lports)
        if ($core) { Write-CcLog -Level DEBUG -Message "-Strict keeps Windows core networking rule $($r.name)"; continue }
        if ($IsDC -and ((Lc ($r.app + ' ' + $r.svc + ' ' + $r.group + ' ' + $r.name)) -match $dcKeep)) { continue }
        $why = '-Strict: not one of ours'
    }
    if ($why) { $off += New-Object PSObject -Property @{ R = $r; Why = $why } }
}

# Show the plan.
$planCsv = New-CcCsv -Name plan -Header @('rule', 'protocol', 'ports', 'from', 'why')
$adds = @()
foreach ($k in $order) {
    $pp = Parse-Port $k
    $adds += New-Object PSObject -Property @{ Name = ('BT allow ' + $k); Proto = $pp.Proto; Ports = $pp.Ports; From = ''; Why = $want[$k] }
}
if ($IsDC) { $adds += New-Object PSObject -Property @{ Name = 'BT allow RPC (DC)'; Proto = 'TCP'; Ports = 'RPC'; From = ''; Why = 'domain controller: RPC dynamic ports' }
             $adds += New-Object PSObject -Property @{ Name = 'BT allow RPC endpoint mapper (DC)'; Proto = 'TCP'; Ports = 'RPC-EPMap'; From = ''; Why = 'domain controller' } }
if ($admins.Count -gt 0) { $adds += New-Object PSObject -Property @{ Name = 'BT allow admin and scoring hosts'; Proto = 'ANY'; Ports = ''; From = ($admins -join ','); Why = 'protected hosts and -AdminFrom: everything' } }
if (-not $NoPing) { $adds += New-Object PSObject -Property @{ Name = 'BT allow ping'; Proto = 'ICMP'; Ports = ''; From = ''; Why = 'ICMP echo (scoring often pings)' } }
foreach ($a in $adds) { Add-CcCsvRow -File $planCsv -Values @($a.Name, $a.Proto, $a.Ports, $a.From, $a.Why) }
# Rules of ours from an earlier run that this plan no longer has (a port now
# in -Exclude, a listener that is gone): removed, so a rerun really closes it.
$addNames = @($adds | ForEach-Object { $_.Name })
$stale = @($rules | Where-Object { $_.group -eq $Group -and $addNames -notcontains $_.name } | ForEach-Object { $_.name } | Select-Object -Unique)
$offCsv = New-CcCsv -Name disabled -Header @('rule', 'program', 'ports', 'why', 'result')

$sum = @()
$sum += ('WN-25 Windows firewall  {0}  {1}' -f [DateTime]::UtcNow.ToString("yyyy-MM-dd HH:mm 'UTC'"), $(if ($Cc.Apply) { 'APPLIED' } else { 'DRY RUN' }))
$sum += ('Host: {0}{1}' -f $Cc.Host, $(if ($IsDC) { '  (domain controller: Active Directory ports kept open)' } else { '' }))
$sum += ''
$sum += 'Profiles: Domain, Private, Public -> ON, block inbound, allow outbound'
$sum += ('Allow in ({0} rules):' -f $adds.Count)
foreach ($a in $adds) { $what = $a.Ports; if ($a.Proto -eq 'ANY') { $what = 'everything from ' + $a.From } elseif ($a.Proto -eq 'ICMP') { $what = 'ping' } else { $what = $a.Ports + '/' + (Lc $a.Proto) }; $sum += ('  {0,-28} {1}' -f $what, $a.Why) }
$na = @(Import-Csv -LiteralPath $notCsv)
if ($na.Count -gt 0) { $sum += ''; $sum += ('NOT opened, though something listens ({0}):' -f $na.Count); foreach ($n in $na) { $sum += ('  {0,-12} {1,-18} {2}' -f $n.port, $n.process, $n.why) } }
if ($stale.Count -gt 0) { $sum += ''; $sum += ('Rules from an earlier WN-25 run no longer wanted, removed ({0}):' -f $stale.Count); foreach ($s in $stale) { $sum += ('  ' + $s) } }
if ($off.Count -gt 0) { $sum += ''; $sum += ('Existing rules turned off ({0}):' -f $off.Count); foreach ($o in $off) { $sum += ('  {0}: {1}' -f $o.R.name, $o.Why) } }
if ($admins.Count -eq 0) { $sum += ''; $sum += 'WARNING: no admin or scoring addresses (protected list "host" entries or -AdminFrom). Only the ports above will reach this box.' }

# =============================================================================
# Apply
# =============================================================================
if (-not $Cc.Apply) {
    foreach ($a in $adds) { Write-CcLog -Level WOULD -Message ('add rule ' + $a.Name) ; $Cc.Would++ }
    foreach ($s in $stale) { Write-CcLog -Level WOULD -Message ('remove old rule ' + $s); $Cc.Would++ }
    foreach ($o in $off) { Write-CcLog -Level WOULD -Message ('turn off rule ' + $o.R.name + ' (' + $o.Why + ')'); $Cc.Would++; Add-CcCsvRow -File $offCsv -Values @($o.R.name, $o.R.app, $o.R.lports, $o.Why, 'would turn off') }
    $sum += ''; $sum += 'Dry run: nothing was changed. Check the plan, fill in the protected list, then add -Apply.'
} else {
    if (Task-Exists) {
        $pend = Pending-Run
        if ($pend) {
            Stop-Cc -Code 2 -Message "a firewall change is still waiting to be kept or rolled back ($pend). Run its keep-firewall.ps1 or rollback.ps1, then run this again"
        }
        # The task is left over from a run that was kept or rolled back (for
        # example kept from a window that could not delete it): remove it.
        Write-CcLog -Level INFO -Message "removing a leftover rollback task $TaskName (its run was already kept or rolled back)"
        Task-Delete
    }
    $exp = Join-Path $Dir 'firewall-before.wfw'
    try { Export-Fw $exp } catch { Stop-Cc -Code 4 -Message ('could not export the firewall first, so nothing was changed: ' + $_.Exception.Message) }
    Add-CcUndo -Description 'WN-25 put the whole firewall back' -Command ('netsh advfirewall import {0}' -f (Q $exp))

    # The rollback and keep scripts, written before anything changes.
    $marker = Join-Path $Dir 'ROLLED_BACK'
    $kept = Join-Path $Dir 'KEPT'
    $fakeLine = ''
    if ($Fake) { $fakeLine = "`$env:BT_WN25_FAKE = $(Q $Fake)`r`n" }
    $rb = Join-Path $Dir 'rollback.ps1'
    [IO.File]::WriteAllText($rb, @"
# WN-25 rollback: puts back the whole firewall from before $Dir
# The scheduled task $TaskName runs this; you can run it by hand too.
$fakeLine`$exp = $(Q $exp)
if (Test-Path -LiteralPath $(Q $kept)) {
    # Kept: nothing to put back.  Remove the task in case keep could not.
    if (`$env:BT_WN25_FAKE) { Remove-Item -LiteralPath (Join-Path `$env:BT_WN25_FAKE 'task.txt') -Force -ErrorAction SilentlyContinue } else { schtasks /delete /tn $TaskName /f | Out-Null }
    exit 0
}
if (`$env:BT_WN25_FAKE) {
    `$d = `$exp + '.d'; `$f = `$env:BT_WN25_FAKE
    if (-not (Test-Path -LiteralPath (Join-Path `$d 'logging.txt'))) { Remove-Item -LiteralPath (Join-Path `$f 'logging.txt') -Force -ErrorAction SilentlyContinue }
    Get-ChildItem -LiteralPath `$d | ForEach-Object { Copy-Item -LiteralPath `$_.FullName -Destination (Join-Path `$f `$_.Name) -Force }
    Remove-Item -LiteralPath (Join-Path `$f 'task.txt') -Force -ErrorAction SilentlyContinue
} else {
    netsh advfirewall import `$exp
    schtasks /delete /tn $TaskName /f
}
[IO.File]::WriteAllText($(Q $marker), [DateTime]::UtcNow.ToString('o'))
"@)
    $kp = Join-Path $Dir 'keep-firewall.ps1'
    [IO.File]::WriteAllText($kp, @"
# WN-25: keep the new firewall.  Run this from a NEW connection (a fresh RDP or
# remote session) - that proves the firewall still lets the team in.
$fakeLine if (Test-Path -LiteralPath $(Q $marker)) { Write-Host 'Too late: the old firewall was already put back. Run WN-25 again.'; exit 1 }
# KEPT first: even if the task cannot be deleted here (not elevated), the
# rollback sees KEPT when it fires and does nothing.
[IO.File]::WriteAllText($(Q $kept), [DateTime]::UtcNow.ToString('o'))
if (`$env:BT_WN25_FAKE) { Remove-Item -LiteralPath (Join-Path `$env:BT_WN25_FAKE 'task.txt') -Force -ErrorAction SilentlyContinue }
else { schtasks /delete /tn $TaskName /f 2>&1 | Out-Null; if (`$LASTEXITCODE -ne 0) { Write-Host 'Note: the rollback task could not be deleted from this window (not elevated); it will fire, see the change was kept, and do nothing.' } }
Write-Host 'Kept: the rollback is cancelled. The new firewall stays.'
"@)

    $timerOk = $true
    if (-not $NoTimer) {
        $when = (Get-Date).AddMinutes($ConfirmMinutes)
        try { Task-Create $when $rb; Write-CcLog -Level INFO -Message ('rollback task set for {0:HH:mm:ss}' -f $when) }
        catch { $timerOk = $false; Stop-Cc -Code 4 -Message ('could not create the rollback task, so nothing was changed: ' + $_.Exception.Message) }
    }

    $okAll = $true
    # Allow rules first, then the profiles: the box is never closed with
    # nothing open.
    foreach ($a in $adds) {
        $aa = $a
        # Same name, but maybe other addresses (a new -AdminFrom): replace it.
        if (Has-Rule $a.Name) {
            $same = $false
            if ($Fake) { $same = (@(F-Read 'rules.csv' | Where-Object { $_.group -eq $Group -and $_.name -eq $aa.Name -and $_.lports -eq $aa.Ports -and $_.raddr -eq $aa.From }).Count -gt 0) }
            else {
                $wantA = Norm-Addrs $aa.From
                $same = (@(@((Fw).Rules) | Where-Object { $_.Grouping -eq $Group -and $_.Name -eq $aa.Name -and (Nz $_.LocalPorts) -eq $(if ($aa.Ports) { $aa.Ports } else { (Nz $_.LocalPorts) }) -and (Norm-Addrs (Nz $_.RemoteAddresses)) -eq $wantA }).Count -gt 0)
            }
            if ($same) { Write-CcLog -Level DEBUG -Message ('rule already there: ' + $a.Name); continue }
            [void](Invoke-CcChange -Description ('replace rule ' + $a.Name) -Action { if ($Fake) { F-Write 'rules.csv' $RuleCols @(F-Read 'rules.csv' | Where-Object { -not ($_.group -eq $Group -and $_.name -eq $aa.Name) }) } else { (Fw).Rules.Remove($aa.Name) } })
        }
        if (-not (Invoke-CcChange -Description ('add rule ' + $a.Name) -Action { Add-Rule $aa.Name $aa.Proto $aa.Ports $aa.From })) { $okAll = $false }
    }
    foreach ($s in $stale) {
        $ss = $s
        if (-not (Invoke-CcChange -Description ('remove old rule ' + $s + ' (not in this plan)') -Action {
                if ($Fake) { F-Write 'rules.csv' $RuleCols @(F-Read 'rules.csv' | Where-Object { -not ($_.group -eq $Group -and $_.name -eq $ss) }) }
                else { while (@(@((Fw).Rules) | Where-Object { $_.Grouping -eq $Group -and $_.Name -eq $ss }).Count -gt 0) { (Fw).Rules.Remove($ss) } }
            })) { $okAll = $false }
    }
    foreach ($o in $off) {
        $oo = $o
        $ok = Invoke-CcChange -Description ('turn off rule ' + $o.R.name + ' (' + $o.Why + ')') -Action { Disable-Rule $oo.R }
        $res = 'turned off'; if (-not $ok) { $res = 'FAILED'; $okAll = $false }
        Add-CcCsvRow -File $offCsv -Values @($o.R.name, $o.R.app, $o.R.lports, $o.Why, $res)
    }
    if (-not (Invoke-CcChange -Description 'all profiles on, block inbound, allow outbound' -Action { Set-Profiles })) { $okAll = $false }
    if (-not $NoLog) { [void](Invoke-CcChange -Description 'log dropped connections (pfirewall.log)' -Action { Set-Logging }) }

    $sum += ''
    if (-not $okAll) { $sum += 'SOME CHANGES FAILED: see the log. The rollback timer still covers you.' }
    if ($NoTimer) {
        $sum += 'No rollback timer (-NoTimer).  To put the old firewall back:'
    } else {
        $sum += ('ROLLBACK at {0:HH:mm} unless kept.  From a NEW connection run:' -f $when)
        $sum += ('  powershell -NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $kp)
        $sum += 'Or to put the old firewall back now:'
    }
    $sum += ('  powershell -NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $rb)
    $sum += ('Later, any time:  WN-25-firewall.ps1 -Out {0} -Undo {1} -Apply' -f $Cc.Out, (Split-Path -Leaf $Dir))
}
[IO.File]::WriteAllLines((Join-Path $Dir 'summary.txt'), [string[]]$sum)
if (-not $Quiet -or $Cc.Apply) { foreach ($l in $sum) { Write-Host $l } }
Write-Host ('All results: ' + $Dir)
Complete-Cc
