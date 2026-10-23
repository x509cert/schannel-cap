$ErrorActionPreference = 'Stop'
$script:repo = Split-Path -Parent $PSScriptRoot
$script:checks = 0

function Assert-True($Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    $script:checks++
}

# All capture, process, and file-existence operations below are mocks.
function pktmon {
    $script:state.Calls.Add("pktmon $($args -join ' ')")
    $global:LASTEXITCODE = 0
    switch ($args[0]) {
        'filter' {
            if ($args[1] -eq 'remove') { $global:LASTEXITCODE = $script:state.RemoveExit }
            if ($args[1] -eq 'add') { $global:LASTEXITCODE = $script:state.AddExit }
        }
        'start' {
            $script:state.StartCount++
            $global:LASTEXITCODE = $script:state.StartExit
            if ($script:state.StartCount -gt 1) { $global:LASTEXITCODE = $script:state.FallbackStartExit }
        }
        'pcapng' {
            $global:LASTEXITCODE = $script:state.ConvertExit
            if ($global:LASTEXITCODE -eq 0 -and $script:state.CreatePcap) { $script:state.PcapExists = $true }
        }
        'etl2pcap' {
            $global:LASTEXITCODE = $script:state.FallbackConvertExit
            if ($global:LASTEXITCODE -eq 0 -and $script:state.CreatePcap) { $script:state.PcapExists = $true }
        }
    }
}

function Start-Process { $script:state.Calls.Add('Start-Process') }
function Stop-Process { $script:state.Calls.Add('Stop-Process') }
function logman { $script:state.Calls.Add('logman'); $global:LASTEXITCODE = 0 }
function Write-Host {
    param(
        [Parameter(ValueFromPipeline = $true)][object]$Object,
        [object]$ForegroundColor,
        [switch]$NoNewline
    )
    process {
        if ($ForegroundColor) { $script:state.Colors.Add("$ForegroundColor=$Object") }
        $script:state.Line += [string]$Object
        if (-not $NoNewline) {
            $script:state.Output.Add($script:state.Line)
            $script:state.Line = ''
        }
    }
}
function Write-Warning { param([string]$Message) $script:state.Warnings.Add($Message) }

function Test-Path {
    param([string]$Path, [string]$LiteralPath, [string]$PathType)
    $target = if ($LiteralPath) { $LiteralPath } else { $Path }
    if ($target -like '*tls.pcapng') { return $script:state.PcapExists }
    if ($target -like '*schannel_failures.csv') { return $script:state.FailuresExist }
    if ($target -eq 'Invoke-TestDecoder') { return $script:state.DecoderExists }
    return $true
}

function Import-Csv {
    [pscustomobject]@{
        Time = '12:00:00.000'; PID = '42'; Process = 'failure-process'
        EventId = '1'; Level = 'Error'; Error = 'synthetic-failure'
    }
}

function Invoke-TestDecoder {
    $script:state.Calls.Add('decoder')
    $global:LASTEXITCODE = $script:state.DecodeExit
    'Time,PID,Process,Side,Source,Dest,Version,Cipher,Group,Class'
    "12:00:00.000,42,success-process,srv,$($script:state.Source),$($script:state.Dest),TLS1.3,$($script:state.Cipher),SecP384r1MLKEM1024,hybrid"
}

function Invoke-Scenario([string]$Name, [hashtable]$Overrides = @{}, [hashtable]$Arguments = @{}) {
    $script:state = @{
        Calls = [System.Collections.Generic.List[string]]::new()
        Output = [System.Collections.Generic.List[string]]::new()
        Colors = [System.Collections.Generic.List[string]]::new()
        Line = ''
        Warnings = [System.Collections.Generic.List[string]]::new()
        RemoveExit = 0; AddExit = 0; StartExit = 0; FallbackStartExit = 0; StartCount = 0
        ConvertExit = 0; FallbackConvertExit = 0; DecodeExit = 0
        PcapExists = $false; CreatePcap = $true; FailuresExist = $true; DecoderExists = $true
        Source = '192.0.2.2:50000'; Dest = '192.0.2.1:443'; Cipher = 'TLS_AES_256_GCM_SHA384'
        Exception = $null
    }
    foreach ($key in $Overrides.Keys) { $script:state[$key] = $Overrides[$key] }
    $path = Join-Path $script:repo "$Name-sch.ps1"
    $text = [IO.File]::ReadAllText($path)
    # Remove elevation only in this in-memory, fully mocked copy.
    $text = $text.Replace('#Requires -RunAsAdministrator', '')
    $text = $text.Replace('$here = Split-Path -Parent $MyInvocation.MyCommand.Path', '$here = $script:repo')
    $text = $text.Replace('$decode = Join-Path $here ''tls_group.exe''', '$decode = ''Invoke-TestDecoder''')
    try {
        & ([scriptblock]::Create($text)) @Arguments
    } catch {
        $script:state.Exception = $_
    }
}

Invoke-Scenario 'start' @{ RemoveExit = 5 } @{ Port = 443 }
Assert-True ($null -ne $script:state.Exception) 'Filter removal must fail closed.'
Assert-True ($script:state.StartCount -eq 0) 'Failed filter removal must not start capture.'
Assert-True (-not ($script:state.Calls -contains 'Start-Process')) 'Failed setup must not launch ETW.'

Invoke-Scenario 'start' @{ AddExit = 87 } @{ Port = 70000; IpA = 'invalid' }
Assert-True ($null -ne $script:state.Exception) 'Rejected filters must fail closed.'
Assert-True ($script:state.StartCount -eq 0) 'Rejected filters must not start capture.'

Invoke-Scenario 'start'
Assert-True ($null -eq $script:state.Exception) 'Intentional unfiltered capture must remain supported.'
Assert-True ($script:state.StartCount -eq 1) 'Unfiltered capture must start.'
Assert-True (-not ($script:state.Calls -like 'pktmon filter add*')) 'Unfiltered capture must not add a filter.'
Assert-True ($script:state.Calls -contains 'Start-Process') 'Successful capture must launch ETW.'

Invoke-Scenario 'start' @{} @{ Port = 443; IpA = '192.0.2.1'; IpB = '192.0.2.2'; FilterPid = 42 }
Assert-True ($null -eq $script:state.Exception) 'Valid filtered capture must succeed.'
Assert-True ($script:state.Calls -contains 'pktmon filter add tls-cap -t TCP -p 443 -i 192.0.2.1 -i 192.0.2.2') 'Filter arguments must remain intact.'

Invoke-Scenario 'start' @{ StartExit = 1; FallbackStartExit = 0 }
Assert-True ($null -eq $script:state.Exception) 'Legacy pktmon start fallback must remain supported.'
Assert-True ($script:state.StartCount -eq 2) 'Failed modern start must invoke fallback.'

Invoke-Scenario 'start' @{ StartExit = 1; FallbackStartExit = 1 }
Assert-True ($null -ne $script:state.Exception) 'Failed capture startup must not claim success.'
Assert-True (-not ($script:state.Calls -contains 'Start-Process')) 'Failed capture startup must not launch ETW.'

Invoke-Scenario 'stop' @{ ConvertExit = 1; FallbackConvertExit = 1; PcapExists = $true }
Assert-True ($null -eq $script:state.Exception) 'Conversion failure must still allow failure-event display.'
Assert-True (@($script:state.Calls -like 'pktmon etl2pcap*').Count -eq 1) 'Conversion failure must try fallback despite an existing capture.'
Assert-True (-not ($script:state.Calls -contains 'decoder')) 'Failed conversion must not decode a stale capture.'
Assert-True (@($script:state.Warnings -like '*unavailable*').Count -eq 1) 'Failed conversion must report unavailable telemetry.'
Assert-True (@($script:state.Output -like '*failure-process*').Count -gt 0) 'Failure events must remain visible.'
Assert-True (@($script:state.Output -like '*not converted or decoded*').Count -eq 1) 'An existing capture must not be described as freshly converted.'

Invoke-Scenario 'stop' @{ ConvertExit = 1; PcapExists = $true }
Assert-True ($null -eq $script:state.Exception) 'Conversion fallback must succeed.'
Assert-True ($script:state.Calls -contains 'decoder') 'Successful conversion fallback must enable decoding.'
Assert-True (@($script:state.Output -like '*success-process*').Count -gt 0) 'Successful decoded results must remain visible.'

Invoke-Scenario 'stop' @{ CreatePcap = $false }
Assert-True (-not ($script:state.Calls -contains 'decoder')) 'A zero conversion exit without an output file must not enable decoding.'
Assert-True ($script:state.Warnings.Count -gt 0) 'A missing conversion output must be reported.'

Invoke-Scenario 'stop' @{ DecodeExit = 9 }
Assert-True ($null -eq $script:state.Exception) 'Decoder failure must still allow failure-event display.'
Assert-True (@($script:state.Output -like '*success-process*').Count -eq 0) 'Failed decoder rows must not be marked successful.'
Assert-True (@($script:state.Output -like '*failure-process*').Count -gt 0) 'Decoder failure must not hide Schannel events.'
Assert-True (@($script:state.Warnings -like '*exit code 9*').Count -eq 1) 'Decoder exit status must be reported.'

Invoke-Scenario 'stop' @{ DecoderExists = $false }
Assert-True ($null -eq $script:state.Exception) 'Missing decoder must not prevent failure-event display.'
Assert-True (-not ($script:state.Calls -contains 'decoder')) 'Missing decoder must not be invoked.'
Assert-True (@($script:state.Output -like '*failure-process*').Count -gt 0) 'Missing decoder must not hide Schannel events.'

Invoke-Scenario 'stop' @{ PcapExists = $true } @{ FailuresOnly = $true }
Assert-True ($null -eq $script:state.Exception) 'FailuresOnly must remain supported.'
Assert-True (-not ($script:state.Calls -contains 'decoder')) 'FailuresOnly must not invoke the decoder.'
Assert-True (-not ($script:state.Calls -like 'pktmon pcapng*')) 'FailuresOnly must not convert captures.'
Assert-True (@($script:state.Output -like '*failure-process*').Count -gt 0) 'FailuresOnly must display Schannel events.'

Invoke-Scenario 'stop' @{} @{ MaskS = $true; MaskD = $true }
Assert-True ($null -eq $script:state.Exception) 'Output masking must remain supported.'
Assert-True (@($script:state.Output -like '*192.XXX.XXX.2:50000*').Count -gt 0) 'Source masking must remain effective.'
Assert-True (@($script:state.Output -like '*192.XXX.XXX.1:443*').Count -gt 0) 'Destination masking must remain effective.'

Invoke-Scenario 'stop' @{} @{ RedactStrings = @('success-process') }
Assert-True ($null -eq $script:state.Exception) 'Output redaction must remain supported.'
Assert-True (@($script:state.Output -like '*success-process*').Count -eq 0) 'Redaction must remove successful rows.'
Assert-True (@($script:state.Output -like '*failure-process*').Count -gt 0) 'Redaction must retain unmatched failures.'

$longIPv6 = '2001:0db8:1234:5678:9abc:def0:abcd:ef01'
$shortIPv6 = '[2001:db8:...:abcd:ef01]'
Invoke-Scenario 'stop' @{ Source = "${longIPv6}:50000"; Dest = "[${longIPv6}]:443" }
Assert-True ($null -eq $script:state.Exception) 'IPv6 output without shortening must succeed.'
Assert-True (($script:state.Output -join "`n").Contains("${longIPv6}:50000")) 'IPv6 endpoints must remain unchanged by default.'
Assert-True (($script:state.Output -join "`n").Contains("[${longIPv6}]:443")) 'Bracketed IPv6 endpoints must remain unchanged by default.'

foreach ($case in @(
    @{ Source = "${longIPv6}:50000"; Dest = "[${longIPv6}]:443";
       ExpectedSource = "${shortIPv6}:50000"; ExpectedDest = "${shortIPv6}:443" },
    @{ Source = '[2001:db8:1234:5678::abcd:ef01]:50000'; Dest = 'fe80:0000:0000:0000:1234:5678:abcd:ef01%12:443';
       ExpectedSource = "${shortIPv6}:50000"; ExpectedDest = '[fe80:0:...:abcd:ef01%12]:443' },
    @{ Source = '[::1]:50000'; Dest = '[2001:db8::1]:443';
       ExpectedSource = '[::1]:50000'; ExpectedDest = '[2001:db8::1]:443' },
    @{ Source = '192.0.2.2:50000'; Dest = 'resolved.example:443';
       ExpectedSource = '192.0.2.2:50000'; ExpectedDest = 'resolved.example:443' }
)) {
    Invoke-Scenario 'stop' @{ Source = $case.Source; Dest = $case.Dest } @{ ShortIPv6 = $true }
    Assert-True ($null -eq $script:state.Exception) 'IPv6 shortening must succeed.'
    $output = $script:state.Output -join "`n"
    Assert-True ($output.Contains($case.ExpectedSource)) "Unexpected shortened source: $($case.Source)"
    Assert-True ($output.Contains($case.ExpectedDest)) "Unexpected shortened destination: $($case.Dest)"
    Assert-True ($output.Contains('failure-process')) 'IPv6 shortening must retain failure rows with unknown endpoints.'
}

Invoke-Scenario 'stop' @{ Source = "${longIPv6}:50000" } @{ ShortIPv6 = $true; MaskD = $true }
Assert-True ($null -eq $script:state.Exception) 'IPv6 shortening must work alongside IPv4 masking.'
Assert-True (($script:state.Output -join "`n").Contains("${shortIPv6}:50000")) 'IPv6 shortening must remain effective alongside masking.'
Assert-True (($script:state.Output -join "`n").Contains('192.XXX.XXX.1:443')) 'IPv4 masking must remain effective alongside shortening.'

Invoke-Scenario 'stop' @{ Source = "${longIPv6}:50000" } @{
    ShortIPv6 = $true; RedactStrings = @($shortIPv6)
}
Assert-True ($null -eq $script:state.Exception) 'Redaction of abbreviated IPv6 endpoints must succeed.'
Assert-True (@($script:state.Output -like '*success-process*').Count -eq 0) 'Redaction must match the displayed IPv6 abbreviation literally.'
Assert-True (@($script:state.Output -like '*failure-process*').Count -gt 0) 'IPv6 redaction must retain unmatched failures.'

# Colors must render on both PowerShell 7.2+ (ANSI) and Windows PowerShell 5.1
# (console colors), without shifting table columns.
Invoke-Scenario 'stop'
Assert-True ($null -eq $script:state.Exception) 'Colored table output must succeed.'
$lines = (($script:state.Output -join "`n") -replace "$([char]27)\[[0-9;]*m", '') -split "\r?\n"
$header = @($lines | Where-Object { $_ -match '^Time +Result ' })
$successLine = @($lines | Where-Object { $_ -like '*success-process*' })
Assert-True ($header.Count -eq 1 -and $successLine.Count -eq 1) 'Table must include one header and one success row.'
Assert-True ($header[0].IndexOf('Group') -eq $successLine[0].IndexOf('SecP384r1MLKEM1024')) 'Cells must stay aligned with their headers.'
Assert-True ($header[0] -match 'Group +Error\s*$' -and $header[0] -notmatch 'EventId|Level') 'Error must directly follow Group; EventId and Level must not be displayed.'
Assert-True (($lines -join "`n").Contains('synthetic-failure')) 'Failure details must remain visible.'
if ($PSStyle) {
    $output = $script:state.Output -join "`n"
    Assert-True ($output.Contains("$($PSStyle.Foreground.Green)SecP384r1MLKEM1024")) 'Hybrid groups must be green.'
    Assert-True ($output.Contains("$($PSStyle.Foreground.Red)Failure")) 'Failure results must be red.'
} else {
    Assert-True ($script:state.Colors -contains 'Green=SecP384r1MLKEM1024') 'Hybrid groups must be green.'
    Assert-True ($script:state.Colors -contains 'Red=Failure') 'Failure results must be red.'
    Assert-True ($script:state.Colors.Count -eq 2) 'Only matching cells may be colored.'
}

Invoke-Scenario 'stop' @{ Cipher = 'TLS_AES_128_GCM_SHA256' }
Assert-True ($null -eq $script:state.Exception) 'Colored 128-bit cipher output must succeed.'
if ($PSStyle) {
    Assert-True (($script:state.Output -join "`n").Contains("$($PSStyle.Foreground.FromRgb(255,165,0))TLS_AES_128_GCM_SHA256")) '128-bit TLS 1.3 ciphers must be orange.'
} else {
    Assert-True ($script:state.Colors -contains 'DarkYellow=TLS_AES_128_GCM_SHA256') '128-bit TLS 1.3 ciphers must use the closest console color to orange.'
}

[Console]::WriteLine("PASS: $script:checks capture-script assertions (mocked; no live capture or process changes).")
