# PowerShell for Penetration Testing

Welcome to the [SnowCap Cyber](https://www.snowcapcyber.com) PowerShell for Penetration TestingGitHub repository. The goal of this repository is to provide you with a some notes that you may find useful when conducting a penetration test. Penetration begins with the ability to profile and map out a network and the systems associated with it.

## Chapter 1 - Introducing PowerShell

PowerShell is a scripting language that has been ported to a number of platforms such as  Microsoft Windows, Linux and Mac OS. Information and resources on how to use and program in PowerShell can be found at the following:

* [PowerShell Documentation](https://learn.microsoft.com/en-us/powershell/)

* [PowerShell on GitHub](https://github.com/PowerShell/PowerShell)

So let us begin with identifying the version of PowerShell that we are running. We can achieve this via examining the $PSVersionTable local variable.
```powershell
PS C:\Program Files\PowerShell\7> $PSVersionTable

Name                           Value
----                           -----
PSVersion                      7.3.0
PSEdition                      Core
GitCommitId                    7.3.0
OS                             Microsoft Windows 10.0.19042
Platform                       Win32NT
PSCompatibleVersions           {1.0, 2.0, 3.0, 4.0…}
PSRemotingProtocolVersion      2.3
SerializationVersion           1.1.0.1
WSManStackVersion              3.0

PS C:\Program Files\PowerShell\7>
```

Now that we know the version of PowerShell that is running on the target system, our next step is understand the execution policy that the target implements for PowerShell scripts. To achieve this we can execute the following.

```powershell
PS C:\Program Files\PowerShell\7> Get-ExecutionPolicy -List

        Scope ExecutionPolicy
        ----- ---------------
MachinePolicy       Undefined
   UserPolicy       Undefined
      Process       Undefined
  CurrentUser       Undefined
 LocalMachine    RemoteSigned

PS C:\Program Files\PowerShell\7>
```

As a scripting language PowerShall can be enabled or disabled on the local machine. To enable Powershell we can use the following command
```powershell
PS C:\> Set-ExecutionPolicy Unrestricted
```

Once we have created the ability to execute PowerShell scripts on the target system we need to identify the modules that are available to us to download and install.  To support software re-use PowerShell makes use of Modules. We can list all available modules using the find-module command are were can search for a Module containing a key word using the Tag option as follows.
```powershell
PS C:\> find-module -tag Azure

Version              Name                                Repository           Description
-------              ----                                ----------           -----------
2.10.3               Az.Accounts                         PSGallery            Microsoft Azure PowerShell - Accounts credential management cmdlets for Azure Resource Manager in Windows PowerShell and PowerShell Core.
5.8.4                AzureRM.profile                     PSGallery            Microsoft Azure PowerShell - Profile credential management cmdlets for Azure Resource Manager.
4.6.1                Azure.Storage                       PSGallery            Microsoft Azure PowerShell - Storage service cmdlets. Manages blobs, queues, tables and files in Microsoft Azure storage accounts
5.1.0                Az.Storage                          PSGallery            Microsoft Azure PowerShell - Storage service data plane and management cmdlets for Azure Resource Manager in Windows PowerShell and PowerShell Co…
4.9.0                Az.KeyVault                         PSGallery            Microsoft Azure PowerShell - Key Vault service cmdlets for Azure Resource Manager in Windows PowerShell and PowerShell Core.
5.1.1                Az.Compute                          PSGallery            Microsoft Azure PowerShell - Compute service cmdlets for Azure Resource Manager in Windows PowerShell and PowerShell Core.  Manages virtual machine
4.0.1                Az.ApiManagement                    PSGallery            Microsoft Azure PowerShell - Api Management service cmdlets for Azure Resource Manager in Windows PowerShell and PowerShell Core.
1.8.0                Az.Automation                       PSGallery            Microsoft Azure PowerShell - Automation service cmdlets for Azure Resource Manager in Windows PowerShell and PowerShell Core.
1.1.4                Az.AnalysisServices                 PSGallery            Microsoft Azure PowerShell - Analysis Services cmdlets for Windows PowerShell and PowerShell Core.
. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .. . . . . . . . . . . . . . . . . . . . . . . .
```
Once we identified the module that we wish to install we can download and install it using the Install-Module command. So in the following we will download and install the SSH module.
```powershell
PS C:\> Install-Module SSH

Untrusted repository
You are installing the modules from an untrusted repository. If you trust this repository, change its InstallationPolicy value by running the Set-PSRepository cmdlet. Are you sure you want to install the modules from
'PSGallery'?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"): Y
PS C:\>
```

We can also import a PowerShell module directly as follows. In the following we will import the functions/cmdlets from the module PowerSploit.psd1.
```powershell
PS C:\> Import-Module .\PowerSploit.psd1
```

We can identify how to use PowerShell module via using the get-help command. In the following we will identify how to use the Get-Location cmdlet/function.
```powershell
PS C:\>get-help Get-Location

NAME
    Get-Location

SYNTAX
    Get-Location [-PSProvider <string[]>] [-PSDrive <string[]>] [<CommonParameters>]

    Get-Location [-Stack] [-StackName <string[]>] [<CommonParameters>]
```

Now that we have the ability to profile PowerShell and find/install modules we can begin to use it to perform a penetration test.

## Chapter 2 - Network Mapping

We can use PowerShell to perform ICMP pings and traceroute. To perform an ICMP ping we simply make use of the PowerShell command as follows. The Test Connection cmdlet sends Internet Control Message Protocol (ICMP) Echo request packets to one or more comma-separated remote hosts and returns the Echo responses. When using Test-Connection we can use and DNS name or an IP address as shown below.
```powershell
PS C:\> Test-Connection www.google.com

Source        Destination     IPV4Address      IPV6Address                              Bytes    Time(ms)
------        -----------     -----------      -----------                              -----    --------
DESKTOP-01    www.google.com  142.250.200.4                                             32       14
DESKTOP-01    www.google.com  142.250.200.4                                             32       12
DESKTOP-01    www.google.com  142.250.200.4                                             32       15
DESKTOP-01    www.google.com  142.250.200.4                                             32       14

PS C:\> Test-Connection 142.250.200.4

Source        Destination     IPV4Address      IPV6Address                              Bytes    Time(ms)
------        -----------     -----------      -----------                              -----    --------
DESKTOP-01    142.250.200.4   142.250.200.4                                             32       18
DESKTOP-01    142.250.200.4   142.250.200.4                                             32       12
DESKTOP-01    142.250.200.4   142.250.200.4                                             32       22
DESKTOP-01    142.250.200.4   142.250.200.4                                             32       13

PS C:\>
```
If a machine can not be reached via ICMP ping then Test-Connection will return an error message. We can also use the Test-Connection command to map out a network. To do this we make use of its TraceRoute functionality
```powershell
PS C:\> Test-NetConnection 1.1.1.1 -TraceRoute

ComputerName           : 1.1.1.1
RemoteAddress          : 1.1.1.1
InterfaceAlias         : WLAN
SourceAddress          : 192.168.1.3
PingSucceeded          : True
PingReplyDetails (RTT) : 5 ms
TraceRoute             : 192.168.1.1
                         85.7.42.1
                         193.134.95.170
                         138.187.131.211
                         138.187.129.97
                         1.1.1.1
```

## Chapter 3 - Port Scanning Tool

The trick when creating and using tools for Penetration Testing is not to reinvent the year. There are a number of port scanning tools for TCP and UDP that we can access via GitHub.

* [PowerShell IPv4 Port Scanner](https://github.com/BornToBeRoot/PowerShell_IPv4PortScanner)

* [PowerShell TCP Port Scanner](https://github.com/zuphzuph/PowerShell-TCP-Port-Scanner)

* [TCP Port Scanner](https://gist.github.com/raandree/60a6677d0a97ea992a8a0b37681d6365)

* [TCP/UDP Port Scanner](https://github.com/calebstewart/Net-Scan)

* [Posh SecMod](https://github.com/darkoperator/Posh-SecMod)

* [PowerCat](https://github.com/besimorhino/powercat)

It should be noted that many of the tools listed above will be detected, and classified as malicious software, by many anti-virus products. However, from a tools and techniques perspective they are useful and add value to out tool set. A Penetration Test begins with us profiling what is on a network. To achieve this we use a technique called an Arp scan. We can achieve this via the Invoke-ARPScan cmdlet from the Posh-SecMod module.
```powershell
PS C:\> Import-Module .\Posh-SecMod.psd1
PS C:\> Invoke-ARPScan -CIDR 192.168.72.0/24

MAC                            Address
---                            -------
00:AF:81:C0:41:21              192.168.71.10
05:67:87:AF:89:C1              192.168.71.61
00:67:32:90:A1:6F              192.168.71.254
```

We can use some of these tools to perform a quick TCP port scan of the target machine. The IPv4PortScan. tool allows is to specify and start and end port number for our scan.

```powershell
PS C:\> IPv4PortScan.ps1 -Computername 172.16,24.145 -StartPort 1 -EndPort 1024

Port               : 53
Protocol           : tcp
ServiceName        : domain
ServiceDescription : Domain Name Server
Status             : Open

Port               : 631
Protocol           : tcp
ServiceName        : ipp
ServiceDescription : IPP (Internet Printing Protocol)
Status             : Open

PS C:\>
```


We can also use the Test-Connection PowerShell command to perform a test on a single port as follows:
```powershell
PS C:\> Test-Connection -TargetName 192.168.2.11 -TcpPort 443
```
Because we can use Test-Connection to test that a TCP port is open, when we can write a simple scripted to test every port in a list. It is important to note that this technique is not fast compares with tools such as NMAP.
```powershell
$ipaddress = 192.168.2.11
for ($counter=1; $counter -le 65535 ; $counter++)
{
  Test-Connection -TargetName 192.168.2.11 -TcpPort $counter
}
```

Rather than port scan one IP address at a time write a PowerShell application that will read DNS name and IP addresses from a file and and then scan a set of TCP ports from a file.

```powershell
$HOSTFILE = Get-Content "C:\HOSTS.txt"
$PORTFILE = Get-Content "C:\PORTS.txt"
foreach ($HOSTLINE in $HOSTFILE)
  {
    foreach ($PORTLINE in $PORTFILE)
    {
      $STATUS=(New-Object System.Net.Sockets.TcpClient).ConnectAsync($HOSTLINE, $PORTLINE).Wait(1000)
      Write-Output "$HOSTLINE, $PORTLINE, Status: $STATUS"
    }
}
```

## Chapter 4 - Banner Grabbing

Once we have mapped out the structure and topology of a network the next stage in the Penetration Testing process is to capture version information about the services running. We can do this in PowerShell via the application of a set of commands.  List a list of open ports running on a target system on the network we can use specific PowerShell commands to access specific ports.

We can use the Invoke-WebRequest command to get the version information associated with a Web Server.
```powershell
$url = 'https://www.snowcapcyber.com'
$result = Invoke-WebRequest -Method GET -Uri $url -UseBasicParsing
$result.RawContent
```

The above PowerShell defines a URL and then uses the Invoke-WebRequest command to execute the GET HTTP verb on the Server. It should be noted that this command will allow us to execute a other HTTP verbs.
```powershell
HTTP/1.1 200 OK
Link: <https://www.snowcapcyber.com/wp-json/>; rel="https://api.org/", <https://www.snowcapcyber.com/wp-json/wp/v2/pages/11822>; rel="alternate"; type="application/json", <https://www.snowcapcyber.com/>; rel=shortlink, <https://www.snowcapcyber.com/wp-json/>; rel="https://api.org/", <https://www.snowcapcyber.com/wp-json/wp/v2/pages/11822>; rel="alternate"; type="application/json", <https://www.snowcapcyber.com/>; rel=shortlink
Pragma: public
Strict-Transport-Security: max-age=63072000; includeSubdomains;
Upgrade: h2
Connection: Upgrade
Access-Control-Allow-Origin: *
Cache-Control: max-age=0, public
Content-Type: text/html; charset=UTF-8
Date: Sat, 20 Feb 2021 16:08:24 GMT
Expires: Sat, 20 Feb 2021 14:06:05 GMT
ETag: "b952b112b53c6a67782fff33f7ab4e37"
Last-Modified: Sat, 20 Feb 2021 13:06:05 GMT
Server: Apache/2.4.29 (Ubuntu)
X-Powered-By: W3 Total Cache/2.1.0258=
```

Analysis of the above allows us to identify the server type and version number. This can then be used to identify potential vulnerabilities. Once we have identified the ports that are open we can make use of a REST API to identify the IP Address of a target machine. To achieve this we make use of the following
```powershell
PS C:\> Invoke-RestMethod -Uri https://snowcapcyber.com
ip       : 18.193.36.153
hostname : d1-hitch-eu-nlb-e064e2845fd0c838.elb.eu-central-1.amazonaws.com
city     : Droitwich
region   : Droitwich
country  : UK
loc      : 52.2616° N, 2.1526° W
org      : Amazon Technologies Inc. (AT-88-Z)
postal   : WR9 9AY
timezone : Europe/London
readme   : https://snowcapcyber.com

```

## Chapter 5 - User Profiling

Once we have exploited a system we start to profile a system using a set of PowerShell commands. We can start be listing the users on the target system.
```powershell
PS C:\> get-localuser
Name               Enabled Description
----               ------- -----------
Administrator      False   Built-in account for administering the computer/domain
andre              True
Andrew Blyth       True
DefaultAccount     False   A user account managed by the system.
Guest              False   Built-in account for guest access to the computer/domain
WDAGUtilityAccount False   A user account managed and used by the system for Windows
```

Now that we have a list of users we profile a given user in greater detail. To achieve this we use the JJJ command and specify the username that we are interested in.
```powershell
PS C:\> get-localuser -name "Andrew Blyth" | select *
AccountExpires         :
Description            :
Enabled                : True
FullName               :
PasswordChangeableDate : 02/07/2022 21:09:44
PasswordExpires        :
UserMayChangePassword  : True
PasswordRequired       : False
PasswordLastSet        : 02/07/2022 21:09:44
LastLogon              : 19/08/2022 17:14:13
Name                   : Andrew Blyth
SID                    : S-1-5-21-5082059827-597078506-5194163137-1011
PrincipalSource        : Local
ObjectClass            : User
```

Our next step is to identify the SID associated with a specific user.. The SID of a user allows us to identify the RID and Domain SID.

```powershell
PS C:\> $username='ajcblyth'
PS C:\> $user = New-Object System.Security.Principal.NTAccount($username)
PS C:\> $sid = $user.Translate([System.Security.Principal.SecurityIdentifier])
PS C:\> $sid.Value

S-1-5-21-5082059827-597078506-5194163137-1011
```

Once we have identified a SID for a given domain then we can start to use it to identify other users within a domain.
```powershell
$sid='S-1-5-21-5082059827-597078506-5194163137-1025'
$osid = New-Object System.Security.Principal.SecurityIdentifier($sid)
$user = $osid.Translate( [System.Security.Principal.NTAccount])
$user.Value
```

The above script will profile the following output.
```powershell
SNOWCAPCYBER\isutherland
```

Because PowerShell is a scripting language it support a set of commands designed to allow for system administration.  Once of these commands will allow is to query an Active Directory and get a user's SID. In the following we will use the Get-ADUser command.

```powershell
PS C:\> Get-ADUser -Identity 'ajcblyth' | select SID
```

The above script will allow us to identify the SID associated with the username ajcblyth. It will produce the following output.
```powershell
SID
---
S-1-5-21-1528183062-2169693211-1356664787-1205
```

Once we know the SID for the Domain we can then start to cycle through the SID and query every SID in the domain. To do this we make use of a for loop and function that allows us to query the Domain for a given SID. This is shown as follows
```powershell
for ($counter=1; $counter -le 65535 ; $counter++)
{
  $sid = 'S-1-5-21-1528183062-2169693211-1356664787-'+$counter
  $osid = new-object System.Security.Principal.SecurityIdentifier($sid)
  $user = $osid.Translate([System.Security.Principal.NTAccount])
  $user.value
}
```

All of the above let us profile a users within a domain. Once we have profiled user we can look to create a user on the local system or on a Active Directory. In the following we will create a user on a local system. Once we have created a local account we can verify that we have been successful vi a the Get-LocalUser PowerShell command.
```powershell
PS C:\> $PASSWORD= ConvertTo-SecureString –AsPlainText -Force -String MyPa55w0rD
PS C:\> New-LocalUser -Name "jsmith" -Description "John Smith" -Password $PASSWORD
```

Once we have created a local account the next thing that we want to do is to add the account to the local Administrator group. To do this we make use of the Add-LocalGroupMember command.
```powershell
PS C:\> Add-LocalGroupMember -Group "Administrators" -Member "jsmith"
```

Once we have created a new local account and added it to a group then we can check this as follows:
```powershell
PS C:\> Get-LocalGroupMember -Group "Administrators"
ObjectClass Name                 PrincipalSource
----------- ----                 ---------------
User        WIN11\Administrator  Local
User        WIN11\jsmith         Local
```

## Chapter 6 - Profiling Local/Remote Systems

Profiling the target system starts with us profiling the execution policy. The Execution policy defines how, when and where PowerShell Scripts can be executed. To identify the execution policy we can use the Get-ExecutionPolicy PowerShell command.
```powershell
PS C:\>  Get-ExecutionPolicy
```
If you wish to change the PowerShell policy only to the current user, use the following command instead.
```powershell
PS C:\>  Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
```

Profiling the target system continues with us identifying the TCP and UDP ports that are being used. To identify all TCP ports that are being used we can use the  Get-NetTCPConnection PowerShell command as follows.
```powershell
PS C:\>  Get-NetTCPConnection
LocalAddress     LocalPort RemoteAddress   RemotePort State       AppliedSetting
------------     --------- -------------   ---------- -----       --------------
::               445       ::              0          Listen                    
::               135       ::              0          Listen                    
0.0.0.0          65144     0.0.0.0         0          Bound                     
0.0.0.0          65051     0.0.0.0         0          Bound                     
0.0.0.0          49301     0.0.0.0         0          Bound                     
192.168.1.121    65144     21.58.222.106   443        CloseWait   Internet
192.168.1.121    50577     5.32.165.224    3389       Established Internet
192.168.1.121    50409     14.18.226.52    443        Established Internet      
```

We can also use the Get-NetTCPConnection command to identify all TCP ports that are in state Listen.
```powershell
PS C:\>  Get-NetTCPConnection - State Listen
LocalAddress  LocalPort RemoteAddress RemotePort State       AppliedSetting
------------  --------- ------------- ---------- -----       --------------
::            49669     ::            0          Listen                    
0.0.0.0       49669     0.0.0.0       0          Listen                    
0.0.0.0       912       0.0.0.0       0          Listen                    
0.0.0.0       902       0.0.0.0       0          Listen                    
0.0.0.0       135       0.0.0.0       0          Listen                    
```

We can also profile the UDP open ports that have connections to them as follows.
```powershell
PS C:\> Get-NetUDPEndpoint
LocalAddress      LocalPort
------------      ---------
192.168.1.121     1900
169.254.100.173   1900
127.0.0.1         1900
192.168.1.1       138
192.168.1.1       137
```

Or we can list all the UDP ports in the listening state.

```powershell
PS C:\> Get-NetUDPEndpoint -LocalAddress 0.0.0.0
LocalAddress   LocalPort
------------   ---------
0.0.0.0        60108
0.0.0.0        60107
0.0.0.0        54542
0.0.0.0        5355
0.0.0.0        5353
```

Once we have identified the TCP and UDP that are being used by the target system the next stage is to profile the services that are running. To achieve this we will use the Get-Service command.
```powershell
PS C:\> Get-Service

Status   Name               DisplayName
------   ----               -----------
Stopped  AarSvc_be149       Agent Activation Runtime_be149
Running  AdobeARMservice    Adobe Acrobat Update Service
```

Once we have a list of all process on the target system we can filter the output and look for running process.
```powershell
PS C:\> get-service | where-object {$_.Status -eq "Running"}

Status   Name               DisplayName
------   ----               -----------
Running  AdobeARMservice    Adobe Acrobat Update Service
Running  Appinfo            Application Information
Running  AppXSvc            AppX Deployment Service (AppXSVC)
Running  AudioEndpointBu... Windows Audio Endpoint Builder

```

Now that we now the services that are running we can gather information relating to the services such as the account under which the service is running and the location of the executable of the service, and the parameters used to invoke the service.
```powershell
PS C:\> Get-WmiObject win32_service | format-table -AutoSize Name, Startname, Startmode, PathName | Out-String -Width 4096

Name      Startname                   Startmode PathName   
----      ---------                   --------- --------   
Dhcp      NT Authority\LocalService   Auto      C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p      
Dnscache  NT AUTHORITY\NetworkService Auto      C:\Windows\system32\svchost.exe -k NetworkService -p                     
```

We can further out understand of the services running my examining what services are making use of network ports to communicate with the outside world.
```powershell
PS C:\> Get-NetTCPConnection -State Listen |Select-Object -Property LocalPort, State, @{name='ProcessID';expression={(Get-Process -Id $_.OwningProcess). ID}}, @{name='ProcessName';expression={(Get-Process -Id $_.OwningProcess). Path}}

LocalPort  State ProcessID ProcessName
---------  ----- --------- -----------
      135 Listen      1148 C:\Windows\system32\svchost.exe
      912 Listen      3708 C:\Program Files (x86)\VMware\VMware Player\vmware-authd.exe
      902 Listen      3708 C:\Program Files (x86)\VMware\VMware Player\vmware-authd.exe
```

We can expand upon this analysis to include the accounts under which the services ate executing
```powershell
PS C:\> Get-NetTCPConnection -State Listen |Select-Object -Property LocalPort, State, @{name='ProcessID';expression={(Get-Process -IncludeUserName -Id $_.OwningProcess). ID}}, @{name='ProcessName';expression={(Get-Process -IncludeUserName -Id $_.OwningProcess). Path}}, @{name='User';expression={(Get-Process -IncludeUserName -Id $_.OwningProcess). Username}}  | Format-Table -Property * -AutoSize | Out-String -Width 4096

LocalPort  State ProcessID ProcessName                                                  User
---------  ----- --------- -----------                                                  ----
      135 Listen      1148 C:\Windows\system32\svchost.exe                              NT AUTHORITY\NETWORK SERVICE
      912 Listen      3708 C:\Program Files (x86)\VMware\VMware Player\vmware-authd.exe NT AUTHORITY\SYSTEM
      902 Listen      3708 C:\Program Files (x86)\VMware\VMware Player\vmware-authd.exe NT AUTHORITY\SYSTEM
```

The above will list all running processes on the target system. Now that we have an understanding of the process that are running and usernames on the target system we can begin to examine other aspects such as the SMB shares exported. To identify the list of SMB shares we can use the Get-SMBShare command.
```powershell
PS C:> Get-SMBShare
Name   ScopeName Path       Description
----   --------- ----       -----------
ADMIN$ *         C:\Windows Remote Admin
C$     *         C:\        Default share
D$     *         D:\        Default share
E$     *         E:\        Default share
IPC$   *                    Remote IPC
```

Once we have a list of export SMB shares we can profile the access rights on the target system via the JJJ command. Using the HHH command we specify the name of the share that we wish profile.
```powershell
PS C:\> Get-SmbShareAccess -Name C$

Name     ScopeName AccountName               AccessControlType AccessRight
----     --------- -----------               ----------------- -----------
C$       *         BUILTIN\Administrators    Allow             Full
C$       *         NT AUTHORITY\INTERACTIVE  Allow             Full
```

We can make create a new CimSession and the use this as a parameter to the Get-SmbShare command to query the SMB shares on the remote system. This is illustrate as follows
```powershell
$sessionDC01 = New-CimSession -ComputerName dc01.snowcapcyber.com
Get-SmbShare -CimSession $sessionDC01
```

We can also use the Invoke-Command PowerShell command to profile the SMB shares exported by other target systems connected to the network. We achieve this via using the ability of PowerShell to connect to other systems and execute remote commands.
```powershell
PS C:\> Invoke-Command -ComputerName 'dc01.snowcapcyber.com' -ScriptBlock {Get-SmbShare}
```

We can achieve the same results using the WmiObject interface as follows:
```powershell
PS C:\> Get-WmiObject -Class Win32_Share -ComputerName DC01
```

## Recommended Reading

* [Chris Dent, Mastering PowerShell Scripting: Automate and manage your environment using PowerShell 7.1, Packt, 2021](https://www.amazon.co.uk/Mastering-PowerShell-Scripting-Automate-environment/dp/1800206542/ref=sr_1_4?crid=JF1OK6S95NY2&keywords=powershell&qid=1668186716&s=books&sprefix=powershell%2Cstripbooks%2C64&sr=1-4)

* [Lee Holmes, PowerShell Cookbook: Your Complete Guide to Scripting the Ubiquitous Object-Based Shell, O'Reilly, 2021](https://www.amazon.co.uk/PowerShell-Cookbook-Scripting-Ubiquitous-Object-Based/dp/109810160X/ref=sr_1_5?crid=JF1OK6S95NY2&keywords=powershell&qid=1668186716&s=books&sprefix=powershell%2Cstripbooks%2C64&sr=1-5)

* [Chris McNab, Network Security Assessment: Know Your Network, 3rd Edition, O'Reilly, 2016](https://www.amazon.co.uk/Network-Security-Assessment-Know-Your/dp/149191095X/ref=sr_1_1?crid=2RI4CBCKBC79C&keywords=network+security+assessment&qid=1657708066&sprefix=network+security+a%2Caps%2C63&sr=8-1)

* [Tim Bryant, PTFM: Purple Team Field Manual, Independently Published, 2020](https://www.amazon.co.uk/PTFM-Purple-Team-Field-Manual/dp/B08LJV1QCD/ref=sr_1_1?crid=BR8A8SAS3HCN&keywords=ptfm&qid=1657708194&sprefix=ptfm%2Caps%2C167&sr=8-1)

* [Douglas E. Comer, Internetworking With Tcp/Ip Volume I: Principles, Protocol, And Architecture, 6th Edition, Pearson, 2015](https://www.amazon.co.uk/Internetworking-Tcp-Ip-Principles-Architecture/dp/9332550107/ref=sr_1_2?qid=1657708327&refinements=p_27%3ADouglas+E.+Comer&s=books&sr=1-2&text=Douglas+E.+Comer)

## Contact Details

For further information and questions please contact Dr Andrew Blyth, PhD. <ajcblyth@snowcapcyber.com>.
