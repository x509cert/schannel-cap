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
    process { $script:state.Output.Add([string]$Object) }
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
    '12:00:00.000,42,success-process,srv,192.0.2.2:50000,192.0.2.1:443,TLS1.3,TLS_AES_256_GCM_SHA384,SecP384r1MLKEM1024,hybrid'
}

function Invoke-Scenario([string]$Name, [hashtable]$Overrides = @{}, [hashtable]$Arguments = @{}) {
    $script:state = @{
        Calls = [System.Collections.Generic.List[string]]::new()
        Output = [System.Collections.Generic.List[string]]::new()
        Warnings = [System.Collections.Generic.List[string]]::new()
        RemoveExit = 0; AddExit = 0; StartExit = 0; FallbackStartExit = 0; StartCount = 0
        ConvertExit = 0; FallbackConvertExit = 0; DecodeExit = 0
        PcapExists = $false; CreatePcap = $true; FailuresExist = $true; DecoderExists = $true
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

[Console]::WriteLine("PASS: $script:checks capture-script assertions (mocked; no live capture or process changes).")
