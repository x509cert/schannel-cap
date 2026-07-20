<#
  stop-sch.ps1 [-FilterIp <ip>]  --  end capture and decode the negotiated group
    * stops pktmon and the ETW listener
    * converts the ETL to pcapng and runs tls_group.exe
    * optional -FilterIp: only show handshakes involving that IP (either end)
  Self-elevates. Run:  powershell -ExecutionPolicy Bypass -File stop-sch.ps1
#>
param(
    [string]$FilterIp = '',
    [switch]$Resolve            # replace IPs with reverse-DNS names (slow; cached)
)

$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# ---- self-elevate ---------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    $relaunch = @('-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
    if ($FilterIp) { $relaunch += @('-FilterIp',$FilterIp) }
    if ($Resolve)  { $relaunch += '-Resolve' }
    Start-Process powershell -Verb RunAs -ArgumentList $relaunch
    return
}

$etl    = Join-Path $here 'tls.etl'
$pcap   = Join-Path $here 'tls.pcapng'
$connections = Join-Path $here 'connections.txt'
$decode = Join-Path $here 'tls_group.exe'

Write-Host '=== stopping pktmon capture ...'
pktmon stop 2>$null | Out-Null

Write-Host '=== stopping ETW listener / trace session (if running) ...'
Stop-Process -Name schannel_etw -Force -ErrorAction SilentlyContinue
logman stop SchannelRT_Consumer -ets 2>$null | Out-Null

Write-Host "=== converting $etl to pcapng ..."
pktmon pcapng $etl -o $pcap 2>$null | Out-Null
if (-not (Test-Path $pcap)) { pktmon etl2pcap $etl -o $pcap 2>$null | Out-Null }
if (-not (Test-Path $pcap)) {
    Write-Host "[!] pcapng conversion failed. Try:  pktmon pcapng `"$etl`" -o `"$pcap`"" -ForegroundColor Red
    Read-Host 'Press Enter'; return
}

Write-Host ''
if ($FilterIp) { Write-Host "=== negotiated groups (ServerHello) -- filtered to $FilterIp ===" }
else           { Write-Host '=== negotiated groups (ServerHello) ===' }
Write-Host 'Decoding capture (progress below; large captures take a moment)...'

$da = @($pcap, $connections)
if ($FilterIp) { $da += $FilterIp }
$da += '-csv'

$rows = & $decode @da | ConvertFrom-Csv
if (-not $rows) {
    Write-Host '(no TLS ServerHello found in capture)' -ForegroundColor Yellow
} else {
    # collapse duplicates from multi-point capture (same connection + params),
    # then order chronologically
    $rows = $rows |
        Group-Object Source, Dest, Cipher, Group |
        ForEach-Object { $_.Group[0] } |
        Sort-Object Time

    # optional reverse-DNS: replace the IP in Source/Dest with a name (keep port)
    if ($Resolve) {
        # split "ip:port" (or "[v6]:port") into ip + port
        function Split-Ep([string]$ep) {
            if ($ep -match '^\[(.+)\](:\d+)$') { return @($Matches[1], $Matches[2]) }
            if ($ep -match '^(.+):(\d+)$')      { return @($Matches[1], ":$($Matches[2])") }
            return @($ep, '')
        }

        # collect unique IPs across both endpoints first, for a clean % denominator
        $ips = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($r in $rows) {
            $null = $ips.Add((Split-Ep $r.Source)[0])
            $null = $ips.Add((Split-Ep $r.Dest)[0])
        }

        $dns = @{}
        $total = $ips.Count
        Write-Host "Resolving $total unique IP(s) in parallel..."

        # Parallel reverse-DNS with a short timeout so no-PTR IPs don't stall.
        # (ForEach-Object -Parallel requires PowerShell 7+.)
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            $results = $ips | ForEach-Object -Parallel {
                $ip = $_
                $name = $ip
                try {
                    $t = [System.Net.Dns]::GetHostEntryAsync($ip)
                    if ($t.Wait(1500)) { $name = $t.Result.HostName }   # 1.5s cap
                } catch {}
                [pscustomobject]@{ Ip = $ip; Name = $name }
            } -ThrottleLimit 32
            foreach ($r in $results) { $dns[$r.Ip] = $r.Name }
        }
        else {
            # 5.1 fallback: sequential with a percent counter
            $i = 0
            foreach ($ip in $ips) {
                $i++
                Write-Host ("`rResolving DNS names... {0}% ({1}/{2})" -f [int]($i*100/$total), $i, $total) -NoNewline
                $name = $ip
                try { $name = [System.Net.Dns]::GetHostEntry($ip).HostName } catch {}
                $dns[$ip] = $name
            }
            Write-Host "`r                                        `r" -NoNewline
        }

        foreach ($r in $rows) {
            $s = Split-Ep $r.Source
            $d = Split-Ep $r.Dest
            $sn = if ($dns.ContainsKey($s[0])) { $dns[$s[0]] } else { $s[0] }
            $dn = if ($dns.ContainsKey($d[0])) { $dns[$d[0]] } else { $d[0] }
            $r.Source = "$sn$($s[1])"
            $r.Dest   = "$dn$($d[1])"
        }
    }

    # Per-cell color inside a real Format-Table via $PSStyle ANSI (PS 7.2+):
    #   TLS1.2 -> red;  hybrid / pqc group -> green.  Falls back to a plain
    #   table on Windows PowerShell 5.1 (no $PSStyle).
    if ($PSStyle) {
        $red    = $PSStyle.Foreground.Red
        $green  = $PSStyle.Foreground.Green
        $orange = $PSStyle.Foreground.FromRgb(255,165,0)
        $reset  = $PSStyle.Reset
        # keep ANSI codes when the table is captured via Out-String (default
        # 'Host' rendering strips them); restore afterwards.
        $prevRender = $PSStyle.OutputRendering
        $PSStyle.OutputRendering = 'Ansi'
        $tbl = $rows |
            Select-Object `
                Time, PID, Process, Source, Dest,
                @{ N='Version'; E={
                    if ($_.Version -eq 'TLS1.2') { "$red$($_.Version)$reset" } else { $_.Version } }},
                @{ N='Cipher'; E={
                    # TLS 1.3 at the 128-bit tier (AES128 / SHA256) -> orange
                    if ($_.Version -eq 'TLS1.3' -and $_.Cipher -match 'AES_128|SHA256') {
                        "$orange$($_.Cipher)$reset" } else { $_.Cipher } }},
                @{ N='Group'; E={
                    if ($_.Class -in 'hybrid','pqc') { "$green$($_.Group)$reset" }
                    else { $_.Group } }} |
            Format-Table -AutoSize | Out-String -Width 500
        $PSStyle.OutputRendering = $prevRender
        Write-Host $tbl
    } else {
        $rows |
            Format-Table Time, PID, Process, Source, Dest, Version, Cipher, Group -AutoSize |
            Out-String -Width 500 | Write-Host
    }

    # explain any unresolved PID/Process entries
    if ($rows | Where-Object { $_.PID -eq '?' -or $_.Process -eq '?' }) {
        Write-Host ''
        Write-Host "Note: '?' in PID/Process = the connection wasn't in the TCP table when decoded --"
        Write-Host "      typically a short-lived connection that opened and closed between the 200ms"
        Write-Host "      polls, so no owning process could be attributed. The handshake is still valid."
    }
}

Write-Host ''
Write-Host "Full capture: $pcap  (open in Wireshark for detail)."
