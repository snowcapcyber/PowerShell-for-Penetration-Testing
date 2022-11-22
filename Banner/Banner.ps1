<#
    .SYNOPSIS
    Powerful Banner Grabbing Utility
    .DESCRIPTION
    This powerful banner grabbing utility will all you to profile various TCP services.
    .EXAMPLE
    PS C:\> Banner.ps1 -ComputerName ftp.snowcapcyber.co.uk -Port 21
    #>

[CmdletBinding()]
param(
    [Parameter(Position = 0, Mandatory = $true)]
    [string]$ComputerName,
    [Parameter(Position = 1, Mandatory = $true)]
    [ValidateRange(1, 65535)]
    [int]$Port = 1,
)
try {
  $tcpConnection = New-Object System.Net.Sockets.TcpClient($ComputerName, $Port)
  $tcpStream = $tcpConnection.GetStream()
  $reader = New-Object System.IO.StreamReader($tcpStream)
  $writer.AutoFlush = $true
  while ($tcpStream.DataAvailable) { $reader.ReadLine() }
  $reader.Close()
  $tcpConnection.Close()
} catch {
  Write-Host 'Error Processing Request '
}
