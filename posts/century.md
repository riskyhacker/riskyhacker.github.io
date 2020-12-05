---
title: Century 
description: Under The Wire walkthrough series 
date: 2020-08-31
tags:
  - Hacking 
  - Wargames
layout: layouts/post.njk
---

> An Under The Wire wargame.

### Getting into UTW 
``` shell/1/
# SSH into UTW on port `22` (password: century1)
ssh century1@century.underthewire.tech
```

### Level 1
``` shell/1/5
# Objective: Identify build version of PowerShell 
PS C:\users\century1\desktop> $PSVersionTable

Name                           Value
----                           -----
PSVersion                      5.1.14393.3866
PSEdition                      Desktop
PSCompatibleVersions           {1.0, 2.0, 3.0, 4.0...}
BuildVersion                   10.0.14393.3866
CLRVersion                     4.0.30319.42000
WSManStackVersion              3.0
PSRemotingProtocolVersion      2.3
SerializationVersion           1.1.0.1

PS C:\users\century1\desktop>
```

### Level 2
``` shell/12/16
# Objective: List file names (Google Invoke-WebRequest: PS version of wget)
PS C:\users\century2\desktop> Get-ChildItem


    Directory: C:\users\century2\desktop


    Mode                LastWriteTime         Length Name
    ----                -------------         ------ ----
    -a----        8/30/2018   3:29 AM            693 443


PS C:\users\century2\desktop> Get-ChildItem | Select-Object -Property Name

    Name
    ----
    443


PS C:\users\century2\desktop> # invoke-webrequest443
```

### Level 3
``` shell/20,26/24,30
# Objective: Count the number of files in a directory
PS C:\users\century3\desktop> Get-ChildItem


    Directory: C:\users\century3\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        8/30/2018   3:29 AM             33 countme1012
-a----        8/30/2018   3:29 AM             33 countme1064
-a----        8/30/2018   3:29 AM             33 countme1079
...
...
...
-a----        8/30/2018   3:29 AM             33 countme929
-a----        8/30/2018   3:29 AM             33 countme972
-a----        8/30/2018   3:29 AM             33 countme996


PS C:\users\century3\desktop> Get-ChildItem | Measure-Object -line

Lines Words Characters Property
----- ----- ---------- --------
  123

PS C:\users\century3\desktop> Get-ChildItem | Measure-Object | select count

Count
-----
  123


PS C:\users\century3\desktop>
```

### Level 4
``` shell/21/29
# Objective: Read directory with whitespace in file name
PS C:\users\century4\desktop> get-childitem


    Directory: C:\users\century4\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        6/12/2020   5:49 PM                -
d-----        6/12/2020   5:48 PM                61580
d-----        5/23/2020   9:19 PM                asd
d-----        8/30/2018   3:29 AM                Can You Open Me
d-----        7/27/2020  12:43 AM                eReja
d-----         3/8/2020   3:17 AM                folder
d-----        6/10/2020   5:13 AM                hello
d-----        6/10/2020   5:15 AM                hello.txt
d-----        6/12/2020   5:50 PM                zipped
-a----         3/8/2020   2:59 AM              0 61580.zip


PS C:\users\century4\desktop> Get-ChildItem '.\Can You Open Me'


    Directory: C:\users\century4\desktop\Can You Open Me


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        8/30/2018   3:29 AM             24 61580


PS C:\users\century4\desktop>
```

### Level 5
``` shell/1,39/21,40
# Objective: Determine short name of the domain
PS C:\users\century5\desktop> Get-ADDomain


AllowedDNSSuffixes                 : {}
ChildDomains                       : {}
ComputersContainer                 : CN=Computers,DC=underthewire,DC=tech
DeletedObjectsContainer            : CN=Deleted Objects,DC=underthewire,DC=tech
DistinguishedName                  : DC=underthewire,DC=tech
DNSRoot                            : underthewire.tech
DomainControllersContainer         : OU=Domain Controllers,DC=underthewire,DC=tech
DomainMode                         : Windows2016Domain
DomainSID                          : S-1-5-21-758131494-606461608-3556270690
ForeignSecurityPrincipalsContainer : CN=ForeignSecurityPrincipals,DC=underthewire,DC=tech
Forest                             : underthewire.tech
InfrastructureMaster               : utw.underthewire.tech
LastLogonReplicationInterval       :
LinkedGroupPolicyObjects           : {cn={ECB4A7C0-B4E1-41B1-9E89-161CFA679999},cn=policies,cn=system,DC=underthewire,DC=tech,
                                     CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=underthewire,DC=tech}
LostAndFoundContainer              : CN=LostAndFound,DC=underthewire,DC=tech
ManagedBy                          :
Name                               : underthewire
NetBIOSName                        : underthewire
ObjectClass                        : domainDNS
ObjectGUID                         : bdccf3ad-b495-4d86-a94c-60f0d832e6f0
ParentDomain                       :
PDCEmulator                        : utw.underthewire.tech
PublicKeyRequiredPasswordRolling   : True
QuotasContainer                    : CN=NTDS Quotas,DC=underthewire,DC=tech
ReadOnlyReplicaDirectoryServers    : {}
ReplicaDirectoryServers            : {utw.underthewire.tech}
RIDMaster                          : utw.underthewire.tech
SubordinateReferences              : {DC=ForestDnsZones,DC=underthewire,DC=tech, DC=DomainDnsZones,DC=underthewire,DC=tech,
                                     CN=Configuration,DC=underthewire,DC=tech}
SystemsContainer                   : CN=System,DC=underthewire,DC=tech
UsersContainer                     : CN=Users,DC=underthewire,DC=tech



PS C:\users\century5\desktop> $env:USERDOMAIN
underthewire
PS C:\users\century5\desktop>
PS C:\users\century5\desktop> ls


    Directory: C:\users\century5\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        8/30/2018   3:29 AM             54 3347


PS C:\users\century5\desktop>
```

### Level 6
``` shell/1/5
# Objective: Count the number of subdirectories in a directory  
PS C:\users\century6\desktop> Get-ChildItem -Directory | Measure-Object -line

Lines Words Characters Property
----- ----- ---------- --------
  197


PS C:\users\century6\desktop>
```

### Level 7
``` shell/2/10
# Objective: Locate a given file name (readme) amongst various folders
# Key insight: Search in contacts, desktop, documents, downloads, favorites, music or videos 
PS C:\users\century7\desktop> Get-ChildItem -Path ..\Desktop,..\Downloads,..\Favorites,..\Music,..\Videos -Filter '*readme*'


    Directory: C:\users\century7\Downloads


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        8/30/2018   3:29 AM              7 Readme.txt


PS C:\users\century7\desktop> Get-Content ..\Downloads\Readme.txt
7points
PS C:\users\century7\desktop>
```

### Level 8
``` shell/12/16
# Objective: Count the number of unique entries in a file
PS C:\users\century8\desktop> Get-ChildItem


    Directory: C:\users\century8\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        8/30/2018   3:33 AM          15858 unique.txt


PS C:\users\century8\desktop> Get-Content .\unique.txt | Select-Object -Unique | Measure-Object | select count

Count
-----
  696


PS C:\users\century8\desktop>

```

### Level 9
``` shell/2/3
# Objective: Locate the 161th word in a file
# Key insight: off-by-one error
PS C:\users\century9\desktop> (Get-Content .\Word_File.txt)[161]
pierid
PS C:\users\century9\desktop>
```

### Level 10
``` shell/12,21,42,95/18,24,36,66,70-72,99
# Objective: Locate the Windows Update service version description
PS C:\users\century10\desktop> Get-ChildItem


    Directory: C:\users\century10\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        8/30/2018   3:34 AM             43 110


PS C:\users\century10\desktop> Get-Service -DisplayName "*update*"

Status   Name               DisplayName
------   ----               -----------
Stopped  tzautoupdate       Auto Time Zone Updater
Stopped  UsoSvc             Update Orchestrator Service for Win...
Stopped  wuauserv           Windows Update


PS C:\users\century10\desktop> Get-Service -Name "Windows Update" | Select-Object *


Name                : wuauserv
RequiredServices    : {rpcss}
CanPauseAndContinue : False
CanShutdown         : False
CanStop             : False
DisplayName         : Windows Update
DependentServices   : {}
MachineName         : .
ServiceName         : wuauserv
ServicesDependedOn  : {rpcss}
ServiceHandle       :
Status              : Stopped
ServiceType         : Win32ShareProcess
StartType           : Manual
Site                :
Container           :


PS C:\users\century10\desktop> Get-WmiObject -Class Win32_Service -Filter "Name='wuauserv'" | Select-Object *


PSComputerName          : UTW
Name                    : wuauserv
Status                  : OK
ExitCode                : 0
DesktopInteract         : False
ErrorControl            : Normal
PathName                : C:\Windows\system32\svchost.exe -k netsvcs
ServiceType             : Share Process
StartMode               : Manual
__GENUS                 : 2
__CLASS                 : Win32_Service
__SUPERCLASS            : Win32_BaseService
__DYNASTY               : CIM_ManagedSystemElement
__RELPATH               : Win32_Service.Name="wuauserv"
__PROPERTY_COUNT        : 26
__DERIVATION            : {Win32_BaseService, CIM_Service, CIM_LogicalElement, CIM_ManagedSystemElement}
__SERVER                : UTW
__NAMESPACE             : root\cimv2
__PATH                  : \\UTW\root\cimv2:Win32_Service.Name="wuauserv"
AcceptPause             : False
AcceptStop              : False
Caption                 : Windows Update
CheckPoint              : 0
CreationClassName       : Win32_Service
DelayedAutoStart        : False
Description             : Enables the detection, download, and installation of updates for Windows and other programs. If this service is disabled,
                          users of this computer will not be able to use Windows Update or its automatic updating feature, and programs will not be
                          able to use the Windows Update Agent (WUA) API.
DisplayName             : Windows Update
InstallDate             :
ProcessId               : 0
ServiceSpecificExitCode : 0
Started                 : False
StartName               : LocalSystem
State                   : Stopped
SystemCreationClassName : Win32_ComputerSystem
SystemName              : UTW
TagId                   : 0
WaitHint                : 0
Scope                   : System.Management.ManagementScope
Path                    : \\UTW\root\cimv2:Win32_Service.Name="wuauserv"
Options                 : System.Management.ObjectGetOptions
ClassPath               : \\UTW\root\cimv2:Win32_Service
Properties              : {AcceptPause, AcceptStop, Caption, CheckPoint...}
SystemProperties        : {__GENUS, __CLASS, __SUPERCLASS, __DYNASTY...}
Qualifiers              : {dynamic, Locale, provider, UUID}
Site                    :
Container               :


PS C:\users\century10\desktop> Get-WmiObject -Class Win32_Service -Filter "Name='wuauserv'" | Select-Object Description

Description
-----------
Enables the detection, download, and installation of updates for Windows and other programs. If this service is disabled, users of this computer wil...

PS C:\users\century10\desktop> (Get-WmiObject -Class Win32_Service -Filter "Name='wuauserv'").Description.Split(" ")[9]
Windows
PS C:\users\century10\desktop> (Get-WmiObject -Class Win32_Service -Filter "Name='wuauserv'").Description.Split(" ")[7]
updates
PS C:\users\century10\desktop>
```

### Level 11
``` shell/1/20
# Objective: Search for hidden files
PS C:\users\century11\desktop> Get-ChildItem -Force -Exclude 'desktop.ini' -Path ..\Desktop,..\Documents,..\Downloads,..\Favorites,..\Music,..\Videos


    Directory: C:\users\century11\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--hsl        8/30/2018   3:11 AM                My Music
d--hsl        8/30/2018   3:11 AM                My Pictures
d--hsl        8/30/2018   3:11 AM                My Videos
d-----        6/16/2020  12:17 AM                WindowsPowerShell


    Directory: C:\users\century11\Downloads


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
--rh--        8/30/2018   3:34 AM             30 secret_sauce


PS C:\users\century11\desktop>
```

### Level 12
``` shell/12,19,34/16,25,41
# Objective: Determine the name of the Domain Controller
PS C:\users\century12\desktop> Get-ChildItem


    Directory: C:\users\century12\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        8/30/2018   3:34 AM             30 _things


PS C:\users\century12\desktop> Get-ADDomainController | Select-Object Name

Name
----
UTW


PS C:\users\century12\desktop> Get-ADComputer UTW


DistinguishedName : CN=UTW,OU=Domain Controllers,DC=underthewire,DC=tech
DNSHostName       : utw.underthewire.tech
Enabled           : True
Name              : UTW
ObjectClass       : computer
ObjectGUID        : 5ca56844-bb73-4234-ac85-eed2d0d01a2e
SamAccountName    : UTW$
SID               : S-1-5-21-758131494-606461608-3556270690-1000
UserPrincipalName :



PS C:\users\century12\desktop> Get-ADComputer UTW -Properties Description


Description       : i_authenticate
DistinguishedName : CN=UTW,OU=Domain Controllers,DC=underthewire,DC=tech
DNSHostName       : utw.underthewire.tech
Enabled           : True
Name              : UTW
ObjectClass       : computer
ObjectGUID        : 5ca56844-bb73-4234-ac85-eed2d0d01a2e
SamAccountName    : UTW$
SID               : S-1-5-21-758131494-606461608-3556270690-1000
UserPrincipalName :


PS C:\users\century12\desktop> 
```


### Level 13
``` shell/1/5
# Objective: Count the number of words in a file
PS C:\users\century13\desktop> (Get-Content .\countmywords).Split(" ") | Measure-Object | select count

Count
-----
  755


PS C:\users\century13\desktop>
```

### Level 14
``` shell/1/5
# Objective: Count the number of occurences of a string in a file
PS C:\users\century14\desktop> (Get-Content .\countpolos).Split(" ") | Select-String -Pattern "(?<!\w)polo" | Measure-Object | select count

Count
-----
  153
```
