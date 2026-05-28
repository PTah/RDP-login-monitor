<#
.SYNOPSIS
    Клиент Security Alert Center для RDP-login-monitor.
.DESCRIPTION
    Dot-source после login_monitor.settings.ps1 и функции Write-Log.
    Ожидает: $UseSAC, $SacUrl, $SacApiKey, $ScriptVersion, $script:InstallRoot.
    Release: 1.2.9-SAC (UTF-8 ingest, title/summary limits, no spool on HTTP 422).
#>

function Get-SacUtf8Bytes {
    param([Parameter(Mandatory = $true)][string]$Text)
    return (New-Object System.Text.UTF8Encoding $false).GetBytes($Text)
}

function Write-SacLog {
    param([string]$Message)
    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log $Message
    } else {
        Write-Host $Message
    }
}

function Get-SacNormalizedMode {
    $m = if ($null -ne $UseSAC) { [string]$UseSAC } else { 'off' }
    return $m.Trim().ToLowerInvariant()
}

function Test-SacConfigured {
    return (-not [string]::IsNullOrWhiteSpace($SacUrl)) -and (-not [string]::IsNullOrWhiteSpace($SacApiKey))
}

function Get-SacBaseUrl {
    if ([string]::IsNullOrWhiteSpace($SacUrl)) { return $null }
    $url = $SacUrl.Trim().TrimEnd('/')
    if ($url -match '/api/v1/events$') {
        $url = $url -replace '/api/v1/events$', ''
    }
    return $url.TrimEnd('/')
}

function Get-SacIngestUrl {
    $base = Get-SacBaseUrl
    if ([string]::IsNullOrWhiteSpace($base)) { return $null }
    return "$base/api/v1/events"
}

function Get-SacSpoolDirResolved {
    if (-not [string]::IsNullOrWhiteSpace($SacSpoolDir)) {
        return $SacSpoolDir.Trim()
    }
    return (Join-Path $script:InstallRoot 'sac-spool')
}

function Get-SacAgentIdFileResolved {
    if (-not [string]::IsNullOrWhiteSpace($SacAgentIdFile)) {
        return $SacAgentIdFile.Trim()
    }
    return (Join-Path $script:InstallRoot 'agent_instance_id')
}

function Get-SacFailCountFileResolved {
    return (Join-Path $script:InstallRoot 'sac-fail.count')
}

function Get-SacAgentInstanceId {
    $idFile = Get-SacAgentIdFileResolved
    $dir = Split-Path -Parent $idFile
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    if (Test-Path -LiteralPath $idFile) {
        $existing = (Get-Content -LiteralPath $idFile -TotalCount 1 -ErrorAction SilentlyContinue)
        if (-not [string]::IsNullOrWhiteSpace($existing)) {
            return $existing.Trim()
        }
    }
    $newId = [guid]::NewGuid().ToString()
    try {
        Set-Content -LiteralPath $idFile -Value $newId -Encoding UTF8 -NoNewline
    } catch { }
    return $newId
}

function Get-SacCategoryForType {
    param([string]$EventType)
    if ($EventType -match '^(ssh\.|auth\.|rdp\.)') { return 'auth' }
    if ($EventType -match '^privilege\.') { return 'privilege' }
    if ($EventType -match '^session\.') { return 'session' }
    if ($EventType -match '^report\.') { return 'report' }
    if ($EventType -match '^rdg\.') { return 'network' }
    return 'agent'
}

function Limit-SacString {
    param(
        [string]$Text,
        [int]$MaxLen,
        [string]$Label
    )
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    if ($Text.Length -le $MaxLen) { return $Text }
    Write-SacLog "WARN: SAC truncate $Label $($Text.Length) -> $MaxLen chars (event schema limit)"
    return $Text.Substring(0, $MaxLen)
}

function Get-SacHttpErrorBody {
    param($Exception)
    try {
        if ($null -eq $Exception -or $null -eq $Exception.Response) { return '' }
        $stream = $Exception.Response.GetResponseStream()
        if ($null -eq $stream) { return '' }
        $reader = New-Object System.IO.StreamReader($stream)
        $body = $reader.ReadToEnd()
        $reader.Close()
        return $body
    } catch {
        return ''
    }
}

function New-SacEventPayload {
    param(
        [Parameter(Mandatory = $true)][string]$EventType,
        [Parameter(Mandatory = $true)][string]$Severity,
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][string]$Summary,
        [hashtable]$Details = $null
    )

    $Title = Limit-SacString -Text $Title -MaxLen 256 -Label 'title'
    $Summary = Limit-SacString -Text $Summary -MaxLen 8192 -Label 'summary'

    $payload = [ordered]@{
        schema_version = '1.0'
        event_id       = [guid]::NewGuid().ToString()
        occurred_at    = (Get-Date).ToString('o')
        source         = [ordered]@{
            product            = 'rdp-login-monitor'
            product_version    = if ($ScriptVersion) { [string]$ScriptVersion } else { 'unknown' }
            agent_instance_id  = Get-SacAgentInstanceId
        }
        host           = [ordered]@{
            hostname  = $env:COMPUTERNAME
            os_family = 'windows'
        }
        category       = (Get-SacCategoryForType -EventType $EventType)
        type           = $EventType
        severity       = $Severity
        title          = $Title
        summary        = $Summary
    }
    if ($null -ne $Details -and $Details.Count -gt 0) {
        $payload.details = $Details
    }
    return $payload
}

function Get-SacFailCount {
    $f = Get-SacFailCountFileResolved
    if (-not (Test-Path -LiteralPath $f)) { return 0 }
    $raw = (Get-Content -LiteralPath $f -TotalCount 1 -ErrorAction SilentlyContinue) -replace '\D', ''
    if ([string]::IsNullOrWhiteSpace($raw)) { return 0 }
    return [int]$raw
}

function Set-SacFailCount {
    param([int]$Count)
    $f = Get-SacFailCountFileResolved
    $dir = Split-Path -Parent $f
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    Set-Content -LiteralPath $f -Value ([string]$Count) -Encoding UTF8 -NoNewline
}

function Reset-SacFailCount {
    Set-SacFailCount -Count 0
}

function Test-SacShouldAttemptSend {
    $mode = Get-SacNormalizedMode
    if ($mode -ne 'fallback') { return $true }

    $max = if ($SacFallbackFailures) { [int]$SacFallbackFailures } else { 5 }
    $n = Get-SacFailCount
    if ($n -lt $max) { return $true }

    if (Test-SacHealth) {
        Reset-SacFailCount
        Write-SacLog 'SAC: /health OK, resuming POST (fallback)'
        return $true
    }
    Write-SacLog "WARN: SAC fallback: skip POST ($n>=$max failures), local channels only"
    return $false
}

function Invoke-SacTlsPrep {
    if (-not $SacTlsSkipVerify) { return }
    if (-not $script:SacTlsCallbackRegistered) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        $script:SacTlsCallbackRegistered = $true
    }
}

function Test-SacHealth {
    if (-not (Test-SacConfigured)) { return $false }
    $base = Get-SacBaseUrl
    if ([string]::IsNullOrWhiteSpace($base)) { return $false }

    $timeout = if ($SacTimeoutSec) { [int]$SacTimeoutSec } else { 12 }
    try {
        Invoke-SacTlsPrep
        $resp = Invoke-WebRequest -Uri "$base/health" -Method Get -UseBasicParsing -TimeoutSec $timeout
        return ($resp.StatusCode -eq 200)
    } catch {
        return $false
    }
}

function Write-SacSpoolFile {
    param(
        [string]$EventId,
        [string]$JsonBody
    )
    $dir = Get-SacSpoolDirResolved
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $path = Join-Path $dir "$EventId.json"
    [System.IO.File]::WriteAllText($path, $JsonBody, (New-Object System.Text.UTF8Encoding $false))
}

function Remove-SacSpoolFile {
    param([string]$EventId)
    $path = Join-Path (Get-SacSpoolDirResolved) "$EventId.json"
    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
}

function Move-SacSpoolToRejected {
    param([string]$EventId)
    $dir = Get-SacSpoolDirResolved
    $src = Join-Path $dir "$EventId.json"
    if (-not (Test-Path -LiteralPath $src)) { return }
    $rejDir = Join-Path $dir 'rejected'
    if (-not (Test-Path -LiteralPath $rejDir)) {
        New-Item -ItemType Directory -Path $rejDir -Force | Out-Null
    }
    $dst = Join-Path $rejDir "$EventId.json"
    Move-Item -LiteralPath $src -Destination $dst -Force -ErrorAction SilentlyContinue
}

function Invoke-SacPostPayload {
    param([string]$JsonBody)

    if (-not (Test-SacConfigured)) { return $false }
    if (-not (Test-SacShouldAttemptSend)) { return $false }

    $ingest = Get-SacIngestUrl
    if ([string]::IsNullOrWhiteSpace($ingest)) { return $false }

    $obj = $JsonBody | ConvertFrom-Json
    $eventId = [string]$obj.event_id
    $eventType = [string]$obj.type
    $timeout = if ($SacTimeoutSec) { [int]$SacTimeoutSec } else { 12 }
    $spoolOnFailure = $true

    try {
        Invoke-SacTlsPrep
        $headers = @{
            Authorization     = "Bearer $SacApiKey"
            'Content-Type'    = 'application/json; charset=utf-8'
            'Idempotency-Key' = $eventId
        }
        $bodyBytes = Get-SacUtf8Bytes -Text $JsonBody
        $resp = Invoke-WebRequest -Uri $ingest -Method Post -Headers $headers -Body $bodyBytes -UseBasicParsing -TimeoutSec $timeout
        if ($resp.StatusCode -in 201, 409, 202) {
            Remove-SacSpoolFile -EventId $eventId
            Reset-SacFailCount
            Write-SacLog "SAC: accepted event_id=$eventId type=$eventType"
            return $true
        }
        $body = if ($resp.Content) { $resp.Content } else { '' }
        if ($resp.StatusCode -eq 422) {
            $spoolOnFailure = $false
            Write-SacLog "WARN: SAC POST HTTP 422 validation (not spooled) type=$eventType event_id=$eventId"
        }
        if ($body.Length -gt 0) {
            $snippet = $body.Substring(0, [Math]::Min(800, $body.Length))
            Write-SacLog "WARN: SAC POST HTTP $($resp.StatusCode): $snippet"
        } else {
            Write-SacLog "WARN: SAC POST HTTP $($resp.StatusCode) (empty body)"
        }
    } catch {
        $code = 0
        $body = Get-SacHttpErrorBody -Exception $_.Exception
        if ($_.Exception.Response) {
            $code = [int]$_.Exception.Response.StatusCode
        }
        if ($code -eq 422) {
            $spoolOnFailure = $false
            Write-SacLog "WARN: SAC POST HTTP 422 validation (not spooled) type=$eventType event_id=$eventId"
        }
        $err = $_.Exception.Message
        if ($body.Length -gt 0) {
            $snippet = $body.Substring(0, [Math]::Min(800, $body.Length))
            Write-SacLog "WARN: SAC POST HTTP ${code}: $err | $snippet"
        } else {
            Write-SacLog "WARN: SAC POST HTTP ${code}: $err"
        }
    }

    if (-not $spoolOnFailure) {
        Move-SacSpoolToRejected -EventId $eventId
        return $false
    }

    Write-SacSpoolFile -EventId $eventId -JsonBody $JsonBody
    $max = if ($SacFallbackFailures) { [int]$SacFallbackFailures } else { 5 }
    $n = Get-SacFailCount + 1
    Set-SacFailCount -Count $n
    if ($n -ge $max) {
        Write-SacLog "WARN: SAC fallback: SAC_FALLBACK_FAILURES threshold ($max)"
    }
    return $false
}

function Send-SacEvent {
    param(
        [Parameter(Mandatory = $true)][string]$EventType,
        [Parameter(Mandatory = $true)][string]$Severity,
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][string]$Summary,
        [hashtable]$Details = $null
    )

    if (-not (Test-SacConfigured)) {
        Write-SacLog 'WARN: SAC not configured (SacUrl / SacApiKey)'
        return $false
    }

    $payload = New-SacEventPayload -EventType $EventType -Severity $Severity -Title $Title -Summary $Summary -Details $Details
    $json = $payload | ConvertTo-Json -Depth 8 -Compress
    return (Invoke-SacPostPayload -JsonBody $json)
}

function Send-SacLocalChannels {
    param(
        [string]$TelegramMessage,
        [string]$EmailSubject
    )

    if ([string]::IsNullOrWhiteSpace($TelegramMessage)) { return $false }

    $channels = @(Get-NotifyOrderChannels)
    if ($channels.Count -eq 0) { return $false }

    $anyOk = $false
    foreach ($ch in $channels) {
        $ok = switch ($ch) {
            'telegram' { Send-TelegramMessage -Message $TelegramMessage }
            'email'    { Send-EmailNotification -Message $TelegramMessage -Subject $EmailSubject }
            default    { $false }
        }
        if ($ok) { $anyOk = $true }
    }
    return $anyOk
}

function Test-SacHeartbeatOnlyEventType {
    param([string]$EventType)
    return ($EventType -eq 'agent.heartbeat')
}

function Send-NotifyOrSac {
    param(
        [Parameter(Mandatory = $true)][string]$EventType,
        [Parameter(Mandatory = $true)][string]$Severity,
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][string]$Summary,
        [string]$TelegramMessage = '',
        [string]$EmailSubject = 'RDP Login Monitor',
        [hashtable]$Details = $null
    )

    if ([string]::IsNullOrWhiteSpace($TelegramMessage)) {
        $TelegramMessage = $Summary
    }

    $mode = Get-SacNormalizedMode

    # Периодический heartbeat — только SAC (UI), без Telegram/email в любом режиме.
    if (Test-SacHeartbeatOnlyEventType -EventType $EventType) {
        if ($mode -eq 'off') {
            return $false
        }
        return (Send-SacEvent -EventType $EventType -Severity $Severity -Title $Title -Summary $Summary -Details $Details)
    }

    switch ($mode) {
        'off' {
            return (Send-SacLocalChannels -TelegramMessage $TelegramMessage -EmailSubject $EmailSubject)
        }
        'exclusive' {
            return (Send-SacEvent -EventType $EventType -Severity $Severity -Title $Title -Summary $Summary -Details $Details)
        }
        'dual' {
            Send-SacEvent -EventType $EventType -Severity $Severity -Title $Title -Summary $Summary -Details $Details | Out-Null
            return (Send-SacLocalChannels -TelegramMessage $TelegramMessage -EmailSubject $EmailSubject)
        }
        'fallback' {
            if (Send-SacEvent -EventType $EventType -Severity $Severity -Title $Title -Summary $Summary -Details $Details) {
                return $true
            }
            return (Send-SacLocalChannels -TelegramMessage $TelegramMessage -EmailSubject $EmailSubject)
        }
        default {
            Write-SacLog "WARN: unknown UseSAC=$mode, local channels only"
            return (Send-SacLocalChannels -TelegramMessage $TelegramMessage -EmailSubject $EmailSubject)
        }
    }
}

function Invoke-SacFlushSpool {
    param([int]$MaxFiles = 20)

    $mode = Get-SacNormalizedMode
    if ($mode -eq 'off') { return }
    if (-not (Test-SacConfigured)) { return }

    $dir = Get-SacSpoolDirResolved
    if (-not (Test-Path -LiteralPath $dir)) { return }

    $files = @(Get-ChildItem -LiteralPath $dir -Filter '*.json' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime)
    $count = 0
    foreach ($f in $files) {
        $count++
        if ($count -gt $MaxFiles) { break }
        try {
            $utf8 = New-Object System.Text.UTF8Encoding $false
            $json = [System.IO.File]::ReadAllText($f.FullName, $utf8)
            Invoke-SacPostPayload -JsonBody $json | Out-Null
        } catch {
            Write-SacLog "WARN: SAC spool flush failed for $($f.Name): $($_.Exception.Message)"
        }
    }
}

function Test-SacConnection {
    Write-Host 'SAC check (rdp-login-monitor)'
    Write-Host "UseSAC=$(Get-SacNormalizedMode)"
    switch (Get-SacNormalizedMode) {
        'exclusive' { Write-Host 'Mode exclusive: SAC only' }
        'dual'      { Write-Host 'Mode dual: SAC + local channels' }
        'fallback'  { Write-Host 'Mode fallback: SAC, then local on failure' }
    }
    Write-Host "SacUrl=$SacUrl"
    if (Test-SacConfigured) {
        Write-Host "SAC ingest URL=$(Get-SacIngestUrl)"
    }
    if (-not (Test-SacConfigured)) {
        Write-Error 'SAC: SacUrl or SacApiKey missing'
        return 1
    }
    if (Test-SacHealth) {
        Write-Host 'SAC health: OK'
    } else {
        Write-Error 'SAC health: FAIL'
        return 1
    }
    if (Send-SacEvent -EventType 'agent.test' -Severity 'info' -Title 'SAC test' -Summary 'rdp-login-monitor CheckSac') {
        Write-Host 'SAC ingest agent.test: OK (expected HTTP 201)'
        return 0
    }
    Write-Error 'SAC ingest agent.test: FAIL'
    return 1
}
