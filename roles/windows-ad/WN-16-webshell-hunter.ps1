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

# >>> BT-LIB
# Development copy: find lib/lib.ps1 by walking up from this file.  The build
# step (tools/build.sh, LB-03) replaces this whole block with the library
# itself, so the built script is a single standalone file.
$ccDir = Split-Path -Parent $MyInvocation.MyCommand.Path
while ($ccDir -and -not (Test-Path -LiteralPath (Join-Path (Join-Path $ccDir 'lib') 'lib.ps1'))) { $ccDir = Split-Path -Parent $ccDir }
if (-not $ccDir) { Write-Host 'cannot find lib/lib.ps1 above this script'; exit 3 }
. (Join-Path (Join-Path $ccDir 'lib') 'lib.ps1')
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
