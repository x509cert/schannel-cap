#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Stop the TLS capture and show a colored table of TLS results.

.DESCRIPTION
    Stops pktmon and the ETW listener, converts tls.etl to tls.pcapng, decodes
    it with tls_group.exe, and shows successful handshakes plus Schannel
    failures. Run from an elevated PowerShell window.

    Options:
      -FilterIp <ip>             Only show successful handshakes involving this
                                 IP (either endpoint).
      -FailuresOnly              Only show Schannel warning, error, and critical
                                 events; skips pcapng conversion and decoding.
      -Resolve                   Replace IPs with reverse-DNS names (slow).
      -MaskS                     Mask source IPv4 octets 2 and 3 (a.XXX.XXX.d).
      -MaskD                     Mask destination IPv4 octets 2 and 3.
      -ShortIPv6                 Abbreviate IPv6 endpoints to their first and
                                 last two groups (display only).
      -RedactStrings <string[]>  Omit table rows containing any of these strings
                                 (literal, case-insensitive).
      -?                         Show this help.

    Examples:
      .\stop-sch.ps1
      .\stop-sch.ps1 -FilterIp 192.168.1.52 -ShortIPv6
      .\stop-sch.ps1 -MaskS -MaskD -RedactStrings svchost.exe, msedge.exe
      powershell -ExecutionPolicy Bypass -File stop-sch.ps1 -FailuresOnly
#>
param(
    [string]$FilterIp = '',
    [switch]$FailuresOnly,
    [switch]$Resolve,           # replace IPs with reverse-DNS names (slow; cached)
    [switch]$MaskS,
    [switch]$MaskD,
    [string[]]$RedactStrings = @(),
    [switch]$ShortIPv6
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

    if ($ShortIPv6) {
        function Shorten-IPv6Endpoint([string]$endpoint) {
            if ($endpoint -match '^\[(.+)\](:\d+)$' -or
                $endpoint -match '^(.+)(:\d+)$') {
                $address = $Matches[1]
                $port = $Matches[2]
                $ip = $null
                if ([System.Net.IPAddress]::TryParse($address, [ref]$ip) -and
                    $ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
                    $bytes = $ip.GetAddressBytes()
                    $groups = @(for ($i = 0; $i -lt 16; $i += 2) {
                        '{0:x}' -f ([int]$bytes[$i] * 256 + $bytes[$i + 1])
                    })
                    $short = '{0}:{1}:...:{2}:{3}' -f $groups[0], $groups[1], $groups[6], $groups[7]
                    if ($address -match '%[^%]+$') { $short += $Matches[0] }
                    if ($short.Length -lt $address.Length) { return "[$short]$port" }
                }
            }
            return $endpoint
        }

        foreach ($r in $rows) {
            $r.Source = Shorten-IPv6Endpoint $r.Source
            $r.Dest = Shorten-IPv6Endpoint $r.Dest
        }
    }

    # Redact complete table rows using the values that will actually be shown.
    # IndexOf provides literal matching, so redaction strings are not regexes.
    $redactTerms = @($RedactStrings | Where-Object {
        -not [string]::IsNullOrEmpty($_)
    })
    $tableColumns = @('Time', 'Result', 'PID', 'Process', 'Source', 'Dest',
                      'Version', 'Cipher', 'Group', 'Error')
    if ($redactTerms.Count) {
        $rows = @($rows | Where-Object {
            $row = $_
            $line = ($tableColumns | ForEach-Object {
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

    # Per-cell colors: failure / TLS1.2 -> red; TLS 1.3 at the 128-bit tier
    # (AES128 / SHA256) -> orange; hybrid / pqc group -> green.
    function Get-CellColor($row, [string]$column) {
        switch ($column) {
            'Result'  { if ($row.Result -eq 'Failure') { return 'Red' } }
            'Version' { if ($row.Version -eq 'TLS1.2') { return 'Red' } }
            'Cipher'  {
                if ($row.Version -eq 'TLS1.3' -and $row.Cipher -match 'AES_128|SHA256') {
                    return 'Orange'
                }
            }
            'Group'   { if ($row.Class -in 'hybrid', 'pqc') { return 'Green' } }
        }
        return $null
    }

    if (-not $rows) {
        Write-Host '(no table rows remain after redaction)' -ForegroundColor Yellow
    } elseif ($PSStyle) {
        # PowerShell 7.2+: ANSI colors inside a real Format-Table.
        $ansi = @{
            Red    = $PSStyle.Foreground.Red
            Green  = $PSStyle.Foreground.Green
            Orange = $PSStyle.Foreground.FromRgb(255,165,0)
        }
        $reset = $PSStyle.Reset
        function Format-AnsiCell($row, [string]$column) {
            $color = Get-CellColor $row $column
            if ($color) { "$($ansi[$color])$($row.$column)$reset" } else { $row.$column }
        }
        # keep ANSI codes when the table is captured via Out-String (default
        # 'Host' rendering strips them); restore afterwards.
        $prevRender = $PSStyle.OutputRendering
        $PSStyle.OutputRendering = 'Ansi'
        $tbl = $rows |
            Select-Object `
                Time,
                @{ N='Result'; E={ Format-AnsiCell $_ 'Result' } },
                PID, Process, Source, Dest,
                @{ N='Version'; E={ Format-AnsiCell $_ 'Version' } },
                @{ N='Cipher'; E={ Format-AnsiCell $_ 'Cipher' } },
                @{ N='Group'; E={ Format-AnsiCell $_ 'Group' } },
                Error |
            Format-Table -AutoSize -Wrap | Out-String -Width 500
        $PSStyle.OutputRendering = $prevRender
        Write-Host $tbl
    } else {
        # Windows PowerShell 5.1 has no $PSStyle, and its Format-Table counts
        # ANSI escapes toward column widths, so write aligned cells with console
        # colors instead. ConsoleColor has no orange; DarkYellow is closest.
        $consoleColors = @{ Red = 'Red'; Green = 'Green'; Orange = 'DarkYellow' }
        $widths = @{}
        foreach ($column in $tableColumns) {
            $width = $column.Length
            foreach ($r in $rows) {
                $length = ([string]$r.$column).Length
                if ($length -gt $width) { $width = $length }
            }
            $widths[$column] = $width
        }
        $last = $tableColumns.Count - 1

        Write-Host ''
        Write-Host (($tableColumns | ForEach-Object {
            $_.PadRight($widths[$_]) }) -join ' ').TrimEnd()
        Write-Host (($tableColumns | ForEach-Object {
            ('-' * $_.Length).PadRight($widths[$_]) }) -join ' ').TrimEnd()
        foreach ($r in $rows) {
            $lastValue = $last
            while ($lastValue -gt 0 -and -not [string]$r.($tableColumns[$lastValue])) {
                $lastValue--
            }
            for ($i = 0; $i -le $lastValue; $i++) {
                $column = $tableColumns[$i]
                $value = [string]$r.$column
                $color = Get-CellColor $r $column
                if ($color) {
                    Write-Host $value -NoNewline -ForegroundColor $consoleColors[$color]
                } else {
                    Write-Host $value -NoNewline
                }
                if ($i -lt $lastValue) {
                    Write-Host (' ' * ($widths[$column] - $value.Length + 1)) -NoNewline
                }
            }
            Write-Host ''
        }
        Write-Host ''
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
        Write-Host '      include the connection tuple. Error retains the decoded ETW event properties.'
    }
}

Write-Host ''
if ($captureReady) {
    Write-Host "Full capture: $pcap  (open in Wireshark for detail)."
} elseif (Test-Path -LiteralPath $pcap -PathType Leaf) {
    Write-Host "Existing capture (not converted or decoded this run): $pcap"
}
