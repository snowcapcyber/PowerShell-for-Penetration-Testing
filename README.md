# PowerShell for Penetration Testing

Welcome to the [SnowCap Cyber](https://www.snowcapcyber.com) PowerShell for Penetration TestingGitHub repository. The goal of this repository is to provide you with a some notes that you may find useful when conducting a penetration test. Penetration begins with the ability to profile and map out a network and the systems associated with it.

## Chapter 1 - Port Scanning Tool

We can use PowerShell to perform ICMP pings and traceroute. To perform an ICMP ping we simply make use of the PowerShell command as follows. The Test Connection cmdlet sends Internet Control Message Protocol (ICMP) Echo request packets to one or more comma-separated remote hosts and returns the Echo responses.
```bash
PS C:\> Test-Connection 8.8.8.8
```

We can also use the Test-Connection command to map out a network. To do this we make use of its TraceRoute functionality
```bash
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

## Chapter 2 - Port Scanning Tool

The trick when creating and using tools for Penetration Testing is not to reinvent the year. There are a number of port scanning tools for TCP and UDP that we can access via GitHub.

* [PowerShell IPv4 Port Scanner](https://github.com/BornToBeRoot/PowerShell_IPv4PortScanner)

* [PowerShell TCP Port Scanner](https://github.com/zuphzuph/PowerShell-TCP-Port-Scanner)

* [TCP Port Scanner](https://gist.github.com/raandree/60a6677d0a97ea992a8a0b37681d6365)

* [TCP/UDP Port Scanner](https://github.com/calebstewart/Net-Scan)

We can also use the HHH command to perform a test on a single port as follows:
```bash
PS C:\> Test-Connection -TargetName 192.168.2.11 -TcpPort 443
```

## Recommended Reading

* [Chris Dent, Mastering PowerShell Scripting: Automate and manage your environment using PowerShell 7.1, Packt, 2021](https://www.amazon.co.uk/Mastering-PowerShell-Scripting-Automate-environment/dp/1800206542/ref=sr_1_4?crid=JF1OK6S95NY2&keywords=powershell&qid=1668186716&s=books&sprefix=powershell%2Cstripbooks%2C64&sr=1-4)

* [Lee Holmes, PowerShell Cookbook: Your Complete Guide to Scripting the Ubiquitous Object-Based Shell, O'Reilly, 2021](https://www.amazon.co.uk/PowerShell-Cookbook-Scripting-Ubiquitous-Object-Based/dp/109810160X/ref=sr_1_5?crid=JF1OK6S95NY2&keywords=powershell&qid=1668186716&s=books&sprefix=powershell%2Cstripbooks%2C64&sr=1-5)

* [Chris McNab, Network Security Assessment: Know Your Network, 3rd Edition, O'Reilly, 2016](https://www.amazon.co.uk/Network-Security-Assessment-Know-Your/dp/149191095X/ref=sr_1_1?crid=2RI4CBCKBC79C&keywords=network+security+assessment&qid=1657708066&sprefix=network+security+a%2Caps%2C63&sr=8-1)

* [Tim Bryant, PTFM: Purple Team Field Manual, Independently Published, 2020](https://www.amazon.co.uk/PTFM-Purple-Team-Field-Manual/dp/B08LJV1QCD/ref=sr_1_1?crid=BR8A8SAS3HCN&keywords=ptfm&qid=1657708194&sprefix=ptfm%2Caps%2C167&sr=8-1)

* [Douglas E. Comer, Internetworking With Tcp/Ip Volume I: Principles, Protocol, And Architecture, 6th Edition, Pearson, 2015](https://www.amazon.co.uk/Internetworking-Tcp-Ip-Principles-Architecture/dp/9332550107/ref=sr_1_2?qid=1657708327&refinements=p_27%3ADouglas+E.+Comer&s=books&sr=1-2&text=Douglas+E.+Comer)

## Contact Details

For further information and questions please contact Dr Andrew Blyth, PhD. <ajcblyth@snowcapcyber.com>.
