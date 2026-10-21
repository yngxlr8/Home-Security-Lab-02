$winIp = '192.168.56.103'                               # Host IP
$log = "$env:USERPROFILE\CyberLab\tcp-fixture.log"      # log file path
$listener = [System.Net.Sockets.TcpListener]::new(      
    [System.Net.IPAddress]::Parse($winIp), 8080)        # port
$listener.Start()
try {
    while ($true) {
        if ($listener.Pending()) {
            $client = $listener.AcceptTcpClient()
            $peer = $client.Client.RemoteEndPoint
            "$(Get-Date -Format o) accepted $peer" |
                Add-Content -LiteralPath $log
            $client.Close()
        }
        Start-Sleep -Milliseconds 100
    }
}
finally { $listener.Stop() }