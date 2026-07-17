<#
  start-sch.ps1 [-FilterPid <int>]  --  begin TLS telemetry capture
    * resets any prior pktmon session
    * starts pktmon packet capture (all components, so loopback is included)
    * runs the ETW listener (writes conns.txt for the PID join)
  Self-elevates. Run:  powershell -ExecutionPolicy Bypass -File start-sch.ps1
#>
param(
    [int]$FilterPid = 0,
    [int]$Port      = 0,        # e.g. 8443 -- only capture this TCP port
    [string]$IpA    = '',       # optional: pin one endpoint
    [string]$IpB    = ''        # optional: pin the other endpoint
)

$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# ---- self-elevate ---------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    $relaunch = @('-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
    if ($FilterPid) { $relaunch += @('-FilterPid',"$FilterPid") }
    if ($Port)      { $relaunch += @('-Port',"$Port") }
    if ($IpA)       { $relaunch += @('-IpA',$IpA) }
    if ($IpB)       { $relaunch += @('-IpB',$IpB) }
    Start-Process powershell -Verb RunAs -ArgumentList $relaunch
    return
}

$etw = Join-Path $here 'schannel_etw.exe'
$etl = Join-Path $here 'tls.etl'
if (-not (Test-Path $etw)) {
    Write-Host '[!] schannel_etw.exe not found - run build.cmd first.' -ForegroundColor Red
    return
}

Write-Host '=== resetting any prior pktmon session ...'
pktmon stop  2>$null | Out-Null
pktmon reset 2>$null | Out-Null

# ---- narrow the capture so the ETL stays small ---------------------------
# One filter entry AND-s its conditions; without any filter, everything is
# captured. Pin the port (and optionally both hosts) so noise never hits disk.
pktmon filter remove 2>$null | Out-Null
if ($Port -or $IpA -or $IpB) {
    $fa = @('filter','add','tls-cap','-t','TCP')
    if ($Port) { $fa += @('-p',"$Port") }
    if ($IpA)  { $fa += @('-i',$IpA) }
    if ($IpB)  { $fa += @('-i',$IpB) }
    Write-Host "=== pktmon filter: $($fa[3..($fa.Count-1)] -join ' ')"
    & pktmon @fa | Out-Null
} else {
    Write-Host '=== no capture filter (capturing all traffic) -- pass -Port 8443 to shrink logs'
}

Write-Host '=== starting pktmon packet capture (full packets, all components) ...'
pktmon start --capture --comp all --pkt-size 0 -f $etl 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) { pktmon start --capture --pkt-size 0 -f $etl | Out-Null }

Write-Host '=== launching ETW listener (conns.txt) in a new window ...'
if ($FilterPid) {
    Start-Process -FilePath $etw -ArgumentList @("$FilterPid") -WorkingDirectory $here
} else {
    Start-Process -FilePath $etw -WorkingDirectory $here
}

Write-Host ''
Write-Host 'Capture running. Generate TLS traffic (ideally from another host to this box),'
Write-Host 'then run  stop-sch.ps1 [filter-ip]  to stop and decode the negotiated group.'
if (-not ($Port -or $IpA -or $IpB)) {
    Write-Host ''
    Write-Host 'TIP: to keep the log small, filter the capture, e.g.:' -ForegroundColor Yellow
    Write-Host '     start-sch.ps1 -Port 8443 -IpA 192.168.1.168 -IpB 192.168.1.52' -ForegroundColor Yellow
}
