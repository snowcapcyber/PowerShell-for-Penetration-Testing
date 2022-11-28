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
    [int]$Port = 23
)
try {
    #
    #
    #
    #
    $socket = New-Object System.Net.Sockets.TcpClient($ComputerName, $Port)
    #
    #
    #
    write-host "Creating a connection to: " $ipaddress " on TCP port: " $Port
    $stream = $socket.GetStream( )
    $writer = New-Object System.IO.StreamWriter( $stream )
    $buffer = New-Object System.Byte[] 1024
    $encoding = New-Object System.Text.AsciiEncoding
    #
    #
    #
    try {
        while( $true )
        {
                # 
                start-sleep -m 500
                Write-Host -NoNewline "prompt> "
                $command = Read-Host
                $writer.WriteLine($command)
                while( $stream.DataAvailable )
                {
                    #         
                    $read = $stream.Read( $buffer, 0, 1024 )
                    Write-Host -n ($encoding.GetString( $buffer, 0, $read ))
                }
                #
                $command = Read-Host
                $writer.WriteLine( $command )
                $writer.Flush( )
        }
    }
    #
    catch {
    }
}
#
catch {
    write-host "Error processing network request on IP Address: " $ComputerName
}
#
#
#
$writer.Close()
$stream.Close()
$socket.Close()
#
#
#
