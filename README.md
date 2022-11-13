# PowerShell for Penetration Testing

Welcome to the [SnowCap Cyber](https://www.snowcapcyber.com) PowerShell for Penetration TestingGitHub repository. The goal of this repository is to provide you with a some notes that you may find useful when conducting a penetration test. Penetration begins with the ability to profile and map out a network and the systems associated with it.

## Chapter 1 - Introducing PowerShell

PowerShell is a scripting language that has been ported to a number of platforms such as  Microsoft Windows, Linux and Mac OS. Information and resources on how to use and program in PowerShell can be found at the following:

* [PowerShell Documentation](https://learn.microsoft.com/en-us/powershell/)

* [PowerShell on GitHub](https://github.com/PowerShell/PowerShell)

As a scripting language it can be enabled or disabled.

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

We can also use the HHH command to perform a test on a single port as follows:
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

Once we have mapped out the structure and topology of a network the next stage in the Penetration Testing process is to capture version information about the services running. We can do this in PowerShell via the application of a set of commands.  

Once we have identified the ports that are open we can make use of a REST API to identify the IP Address of a target machine. To achieve this we make use of the following
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

Once we have exploited a system we start to profile a system using a set of PowerShell commands. To start with we identify the SID of a user. The SID of a user allows us to identify the RID and Domain SID.

```powershell
$username='ajcblyth'
$user = New-Object System.Security.Principal.NTAccount($username)
$sid = $user.Translate([System.Security.Principal.SecurityIdentifier])
$sid.Value
```

The above PowerShell gives us the following.

```powershell
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
SNOWCAPCYBER\Julian
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

## Chapter 6 - System Profiling

Profiling a target system starts with us identifying the TCP and UDP ports that are being used. To identify all TCP ports that are being used we can use the  Get-NetTCPConnection PowerShell command as follows.
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
## Recommended Reading

* [Chris Dent, Mastering PowerShell Scripting: Automate and manage your environment using PowerShell 7.1, Packt, 2021](https://www.amazon.co.uk/Mastering-PowerShell-Scripting-Automate-environment/dp/1800206542/ref=sr_1_4?crid=JF1OK6S95NY2&keywords=powershell&qid=1668186716&s=books&sprefix=powershell%2Cstripbooks%2C64&sr=1-4)

* [Lee Holmes, PowerShell Cookbook: Your Complete Guide to Scripting the Ubiquitous Object-Based Shell, O'Reilly, 2021](https://www.amazon.co.uk/PowerShell-Cookbook-Scripting-Ubiquitous-Object-Based/dp/109810160X/ref=sr_1_5?crid=JF1OK6S95NY2&keywords=powershell&qid=1668186716&s=books&sprefix=powershell%2Cstripbooks%2C64&sr=1-5)

* [Chris McNab, Network Security Assessment: Know Your Network, 3rd Edition, O'Reilly, 2016](https://www.amazon.co.uk/Network-Security-Assessment-Know-Your/dp/149191095X/ref=sr_1_1?crid=2RI4CBCKBC79C&keywords=network+security+assessment&qid=1657708066&sprefix=network+security+a%2Caps%2C63&sr=8-1)

* [Tim Bryant, PTFM: Purple Team Field Manual, Independently Published, 2020](https://www.amazon.co.uk/PTFM-Purple-Team-Field-Manual/dp/B08LJV1QCD/ref=sr_1_1?crid=BR8A8SAS3HCN&keywords=ptfm&qid=1657708194&sprefix=ptfm%2Caps%2C167&sr=8-1)

* [Douglas E. Comer, Internetworking With Tcp/Ip Volume I: Principles, Protocol, And Architecture, 6th Edition, Pearson, 2015](https://www.amazon.co.uk/Internetworking-Tcp-Ip-Principles-Architecture/dp/9332550107/ref=sr_1_2?qid=1657708327&refinements=p_27%3ADouglas+E.+Comer&s=books&sr=1-2&text=Douglas+E.+Comer)

## Contact Details

For further information and questions please contact Dr Andrew Blyth, PhD. <ajcblyth@snowcapcyber.com>.
