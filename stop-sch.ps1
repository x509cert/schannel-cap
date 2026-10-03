#Requires -RunAsAdministrator

<#
  stop-sch.ps1 [-FilterIp <ip>] [-FailuresOnly] [-MaskS] [-MaskD]
    [-RedactStrings <string[]>]
    -- end capture and decode the negotiated group
    * stops pktmon and the ETW listener
    * converts the ETL to pcapng and runs tls_group.exe
    * optional -FilterIp: only show handshakes involving that IP (either end)
    * optional -FailuresOnly: show only Schannel warning/error/critical events
    * optional -MaskS/-MaskD: mask source/destination IPv4 octets 2 and 3
    * optional -RedactStrings: omit table rows containing any supplied string
  Run from an elevated PowerShell window:
    powershell -ExecutionPolicy Bypass -File stop-sch.ps1
#>
param(
    [string]$FilterIp = '',
    [switch]$FailuresOnly,
    [switch]$Resolve,           # replace IPs with reverse-DNS names (slow; cached)
    [switch]$MaskS,
    [switch]$MaskD,
    [string[]]$RedactStrings = @()
)

$here = Split-Path -Parent $MyInvocation.MyCommand.Path

$etl    = Join-Path $here 'tls.etl'
$pcap   = Join-Path $here 'tls.pcapng'
$connections = Join-Path $here 'connections.txt'
$failures = Join-Path $here 'schannel_failures.csv'
$decode = Join-Path $here 'tls_group.exe'

Write-Host '=== stopping pktmon capture ...'
pktmon stop 2>$null | Out-Null

Write-Host '=== stopping ETW listener / trace session (if running) ...'
Stop-Process -Name schannel_etw -Force -ErrorAction SilentlyContinue
logman stop SchannelRT_Consumer -ets 2>$null | Out-Null

$captureReady = $false
if (-not $FailuresOnly) {
    Write-Host "=== converting $etl to pcapng ..."
    pktmon pcapng $etl -o $pcap 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $pcap -PathType Leaf)) {
        pktmon etl2pcap $etl -o $pcap 2>$null | Out-Null
    }
    $captureReady = $LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $pcap -PathType Leaf)
    if (-not $captureReady) {
        Write-Warning 'Pcapng conversion failed; successful-handshake telemetry is unavailable. Failure events can still be displayed.'
    }
}

Write-Host ''
if ($FailuresOnly) {
    Write-Host '=== Schannel failures ==='
} elseif ($FilterIp) {
    Write-Host "=== TLS results -- successful handshakes filtered to $FilterIp ==="
} else {
    Write-Host '=== TLS results ==='
}

$successRows = @()
$successAvailable = $false
if ($captureReady -and -not (Test-Path -LiteralPath $decode -PathType Leaf)) {
    Write-Warning 'tls_group.exe not found; successful-handshake telemetry is unavailable. Run build.cmd first.'
} elseif ($captureReady) {
    Write-Host 'Decoding capture (progress below; large captures take a moment)...'
    $da = @($pcap, $connections)
    if ($FilterIp) { $da += $FilterIp }
    $da += '-csv'
    $decoded = @(& $decode @da)
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "TLS decoder failed (exit code $LASTEXITCODE); successful-handshake telemetry is unavailable. Failure events can still be displayed."
    } else {
        $successRows = @($decoded | ConvertFrom-Csv)
        $successAvailable = $true
    }

    # collapse duplicates from multi-point capture (same connection + params),
    # then order chronologically
    $successRows = @($successRows |
        Group-Object Source, Dest, Cipher, Group |
        ForEach-Object { $_.Group[0] } |
        ForEach-Object {
            $_ | Select-Object *, @{ N='Result'; E={ 'Success' } },
                @{ N='EventId'; E={ '' } }, @{ N='Level'; E={ '' } },
                @{ N='Error'; E={ '' } }
        })
}

$failureRows = @()
if (Test-Path $failures) {
    $failureRows = @(Import-Csv $failures | ForEach-Object {
        [pscustomobject][ordered]@{
            Time    = $_.Time
            PID     = $_.PID
            Process = $_.Process
            Side    = '?'
            Source  = '?'
            Dest    = '?'
            Version = '?'
            Cipher  = '?'
            Group   = '?'
            Class   = ''
            Result  = 'Failure'
            EventId = $_.EventId
            Level   = $_.Level
            Error   = $_.Error
        }
    } | Group-Object Time, PID, EventId, Error | ForEach-Object { $_.Group[0] })
}

$rows = if ($FailuresOnly) {
    @($failureRows)
} else {
    @($successRows) + @($failureRows)
}
$rows = @($rows | Sort-Object Time)

if (-not $rows) {
    $message = if ($FailuresOnly) {
        '(no Schannel warning, error, or critical events captured)'
    } elseif (-not $successAvailable) {
        '(successful-handshake telemetry unavailable; no Schannel warning, error, or critical events captured)'
    } else {
        '(no TLS successes or failures captured)'
    }
    Write-Host $message -ForegroundColor Yellow
} else {

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
            if ($r.Source -ne '?') { $null = $ips.Add((Split-Ep $r.Source)[0]) }
            if ($r.Dest -ne '?') { $null = $ips.Add((Split-Ep $r.Dest)[0]) }
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
            if ($r.Source -ne '?') {
                $s = Split-Ep $r.Source
                $sn = if ($dns.ContainsKey($s[0])) { $dns[$s[0]] } else { $s[0] }
                $r.Source = "$sn$($s[1])"
            }
            if ($r.Dest -ne '?') {
                $d = Split-Ep $r.Dest
                $dn = if ($dns.ContainsKey($d[0])) { $dns[$d[0]] } else { $d[0] }
                $r.Dest = "$dn$($d[1])"
            }
        }
    }

    function Mask-IPv4Endpoint([string]$endpoint) {
        if ($endpoint -match '^(\d{1,3})\.\d{1,3}\.\d{1,3}\.(\d{1,3})(:\d+)?$') {
            return "$($Matches[1]).XXX.XXX.$($Matches[2])$($Matches[3])"
        }
        return $endpoint
    }

    if ($MaskS -or $MaskD) {
        foreach ($r in $rows) {
            if ($MaskS) { $r.Source = Mask-IPv4Endpoint $r.Source }
            if ($MaskD) { $r.Dest = Mask-IPv4Endpoint $r.Dest }
        }
    }

    # Redact complete table rows using the values that will actually be shown.
    # IndexOf provides literal matching, so redaction strings are not regexes.
    $redactTerms = @($RedactStrings | Where-Object {
        -not [string]::IsNullOrEmpty($_)
    })
    if ($redactTerms.Count) {
        $displayColumns = @('Time', 'Result', 'PID', 'Process', 'Source', 'Dest',
                            'Version', 'Cipher', 'Group', 'EventId', 'Level', 'Error')
        $rows = @($rows | Where-Object {
            $row = $_
            $line = ($displayColumns | ForEach-Object {
                [string]$row.$_
            }) -join ' '

            $redact = $false
            foreach ($term in $redactTerms) {
                if ($line.IndexOf($term, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    $redact = $true
                    break
                }
            }
            -not $redact
        })
    }

    # Per-cell color inside a real Format-Table via $PSStyle ANSI (PS 7.2+):
    #   TLS1.2 -> red;  hybrid / pqc group -> green.  Falls back to a plain
    #   table on Windows PowerShell 5.1 (no $PSStyle).
    if (-not $rows) {
        Write-Host '(no table rows remain after redaction)' -ForegroundColor Yellow
    } elseif ($PSStyle) {
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
                Time,
                @{ N='Result'; E={
                    if ($_.Result -eq 'Failure') { "$red$($_.Result)$reset" }
                    else { $_.Result } }},
                PID, Process, Source, Dest,
                @{ N='Version'; E={
                    if ($_.Version -eq 'TLS1.2') { "$red$($_.Version)$reset" } else { $_.Version } }},
                @{ N='Cipher'; E={
                    # TLS 1.3 at the 128-bit tier (AES128 / SHA256) -> orange
                    if ($_.Version -eq 'TLS1.3' -and $_.Cipher -match 'AES_128|SHA256') {
                        "$orange$($_.Cipher)$reset" } else { $_.Cipher } }},
                @{ N='Group'; E={
                    if ($_.Class -in 'hybrid','pqc') { "$green$($_.Group)$reset" }
                    else { $_.Group } }},
                EventId, Level, Error |
            Format-Table -AutoSize -Wrap | Out-String -Width 500
        $PSStyle.OutputRendering = $prevRender
        Write-Host $tbl
    } else {
        $rows |
            Format-Table Time, Result, PID, Process, Source, Dest, Version,
                Cipher, Group, EventId, Level, Error -AutoSize -Wrap |
            Out-String -Width 500 | Write-Host
    }

    # explain any unresolved PID/Process entries
    if ($rows | Where-Object {
        $_.Result -eq 'Success' -and ($_.PID -eq '?' -or $_.Process -eq '?')
    }) {
        Write-Host ''
        Write-Host "Note: '?' in PID/Process = the connection wasn't in the TCP table when decoded --"
        Write-Host "      typically a short-lived connection that opened and closed between the 200ms"
        Write-Host "      polls, so no owning process could be attributed. The handshake is still valid."
    }
    if ($failureRows) {
        Write-Host ''
        Write-Host "Note: failure endpoints are '?' because Schannel failure events do not reliably"
        Write-Host '      include the connection tuple. EventId and Error retain the ETW diagnostics.'
    }
}

Write-Host ''
if ($captureReady) {
    Write-Host "Full capture: $pcap  (open in Wireshark for detail)."
} elseif (Test-Path -LiteralPath $pcap -PathType Leaf) {
    Write-Host "Existing capture (not converted or decoded this run): $pcap"
}
