<#
.SYNOPSIS
    Клиент Security Alert Center для RDP-login-monitor.
.DESCRIPTION
    Dot-source после login_monitor.settings.ps1 и функции Write-Log.
    Ожидает: $UseSAC, $SacUrl, $SacApiKey, $ScriptVersion, $script:InstallRoot.
    Release: 1.2.13-SAC (fix BOM strip: never StartsWith([char]0xFEFF) on PS strings).
#>

function Test-SacIngestAcceptedStatus {
    param([int]$StatusCode)
    return ($StatusCode -in 201, 409, 202)
}

function Complete-SacIngestSuccess {
    param(
        [string]$EventId,
        [string]$EventType,
        [int]$StatusCode
    )
    Remove-SacSpoolFile -EventId $EventId
    Reset-SacFailCount
    if ($StatusCode -eq 409) {
        Write-SacLog "SAC: duplicate OK (HTTP 409) event_id=$EventId type=$EventType"
    } else {
        Write-SacLog "SAC: accepted event_id=$EventId type=$EventType (HTTP $StatusCode)"
    }
}

function Remove-SacLeadingBomChar {
    param([string]$Text)
    $t = $Text
    # Нельзя $t.StartsWith([char]0xFEFF): в PS нет StartsWith(char), char→string даёт ложные совпадения и срезает '{'.
    while ($t.Length -gt 0 -and [int][char]$t[0] -eq 0xFEFF) {
        Write-SacLog 'WARN: SAC stripped U+FEFF BOM character before JSON body'
        $t = $t.Substring(1)
    }
    return $t
}

function Repair-SacJsonText {
    param([string]$Text)
    $t = Get-SacSingleString -Value $Text -Label 'json body'
    $t = Remove-SacLeadingBomChar -Text $t
    $t = $t.TrimStart()
    if ($t.Length -gt 5 -and $t.StartsWith('null', [System.StringComparison]::Ordinal) -and $t[4] -eq '{') {
        Write-SacLog 'WARN: SAC stripped accidental null prefix before JSON body'
        $t = $t.Substring(4).TrimStart()
    }
    if ($t.Length -gt 0 -and $t[0] -ne '{') {
        $brace = $t.IndexOf('{')
        if ($brace -gt 0) {
            Write-SacLog "WARN: SAC stripped $brace chars before first '{' in JSON body"
            $t = $t.Substring($brace)
        }
    }
    return $t
}

function Get-SacUtf8Bytes {
    param([Parameter(Mandatory = $true)][string]$Text)
    $t = Repair-SacJsonText -Text $Text
    $enc = New-Object System.Text.UTF8Encoding $false
    $bytes = $enc.GetBytes($t)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        Write-SacLog 'WARN: SAC stripped UTF-8 BOM bytes before JSON body'
        $bytes = $bytes[3..($bytes.Length - 1)]
    }
    return $bytes
}

function Write-SacLog {
    param([string]$Message)
    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        [void](Write-Log $Message)
    } else {
        Write-Host $Message
    }
}

function Get-SacSingleString {
    param($Value, [string]$Label)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [System.Array]) {
        $parts = @($Value | Where-Object { $null -ne $_ -and $_ -is [string] -and $_.Length -gt 0 })
        if ($parts.Count -gt 0) {
            if ($parts.Count -gt 1) {
                Write-SacLog "WARN: SAC $Label had $($parts.Count) string parts; using last"
            }
            return [string]$parts[-1]
        }
    }
    return [string]$Value
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
        $existing = Read-SacAgentIdFileText -Path $idFile
        if (-not [string]::IsNullOrWhiteSpace($existing)) {
            $existing = Remove-SacLeadingBomChar -Text $existing.Trim()
            return $existing.Trim()
        }
    }
    $newId = [guid]::NewGuid().ToString()
    try {
        [System.IO.File]::WriteAllText($idFile, $newId, (New-Object System.Text.UTF8Encoding $false))
    } catch { }
    return $newId
}

function Read-SacAgentIdFileText {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $enc = New-Object System.Text.UTF8Encoding $false
    return [System.IO.File]::ReadAllText($Path, $enc).Trim()
}

function Get-SacOccurredAtIso {
    return [DateTimeOffset]::Now.ToString('yyyy-MM-ddTHH:mm:ss.fffK')
}

function Convert-AnyToJsonSerializable {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string] -or $Value -is [bool] -or $Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) {
        return $Value
    }
    if ($Value -is [hashtable] -or $Value -is [System.Collections.IDictionary]) {
        $out = @{}
        foreach ($key in $Value.Keys) {
            $out[[string]$key] = Convert-AnyToJsonSerializable $Value[$key]
        }
        return $out
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $list = New-Object System.Collections.Generic.List[object]
        foreach ($item in $Value) {
            $list.Add((Convert-AnyToJsonSerializable $item)) | Out-Null
        }
        return $list
    }
    return [string]$Value
}

function ConvertTo-SacJsonText {
    param([Parameter(Mandatory = $true)]$Payload)
    $serializable = Convert-AnyToJsonSerializable $Payload
    try {
        Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
        $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $ser.MaxJsonLength = 16777216
        $ser.RecursionLimit = 32
        return ,$ser.Serialize($serializable)
    } catch {
        Write-SacLog "WARN: JavaScriptSerializer unavailable, fallback ConvertTo-Json ($($_.Exception.Message))"
        return ,($serializable | ConvertTo-Json -Depth 12 -Compress)
    }
}

function Get-SacCategoryForType {
    param([string]$EventType)
    if ($EventType -match '^agent\.') { return 'agent' }
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
    param($ErrorRecord)
    if ($null -ne $ErrorRecord -and $null -ne $ErrorRecord.ErrorDetails -and -not [string]::IsNullOrWhiteSpace($ErrorRecord.ErrorDetails.Message)) {
        return [string]$ErrorRecord.ErrorDetails.Message
    }
    $ex = if ($null -ne $ErrorRecord) { $ErrorRecord.Exception } else { $null }
    try {
        if ($null -eq $ex -or $null -eq $ex.Response) { return '' }
        $stream = $ex.Response.GetResponseStream()
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
        occurred_at    = (Get-SacOccurredAtIso)
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

function Write-SacPostBodyDiagnostic {
    param(
        [byte[]]$BodyBytes,
        [string]$EventId
    )
    if ($null -eq $BodyBytes -or $BodyBytes.Length -eq 0) { return }
    $take = [Math]::Min(32, $BodyBytes.Length)
    $hex = (($BodyBytes[0..($take - 1)] | ForEach-Object { '{0:X2}' -f $_ }) -join ' ')
    Write-SacLog "WARN: SAC POST body prefix ($take bytes hex): $hex"
    if ([string]::IsNullOrWhiteSpace($script:InstallRoot)) { return }
    try {
        $logDir = Join-Path $script:InstallRoot 'Logs'
        if (-not (Test-Path -LiteralPath $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        $path = Join-Path $logDir 'sac-last-post.json'
        [System.IO.File]::WriteAllBytes($path, $BodyBytes)
        Write-SacLog "WARN: SAC saved last POST body to $path (event_id=$EventId)"
    } catch {
        Write-SacLog "WARN: SAC could not save sac-last-post.json: $($_.Exception.Message)"
    }
}

function Invoke-SacPostPayload {
    param([string]$JsonBody)

    if (-not (Test-SacConfigured)) { return $false }
    if (-not (Test-SacShouldAttemptSend)) { return $false }

    $ingest = Get-SacIngestUrl
    if ([string]::IsNullOrWhiteSpace($ingest)) { return $false }

    $jsonText = Repair-SacJsonText -Text (Get-SacSingleString -Value $JsonBody -Label 'spool payload')
    if ($jsonText -notmatch '"event_id"\s*:\s*"([0-9a-fA-F-]{36})"') {
        Write-SacLog 'WARN: SAC JSON has no event_id (uuid); skip POST'
        return $false
    }
    $eventId = $Matches[1]
    $eventType = 'unknown'
    if ($jsonText -match '"type"\s*:\s*"([^"]+)"') {
        $eventType = $Matches[1]
    }
    $timeout = if ($SacTimeoutSec) { [int]$SacTimeoutSec } else { 12 }
    $spoolOnFailure = $true

    try {
        Invoke-SacTlsPrep
        $headers = @{
            Authorization     = "Bearer $SacApiKey"
            'Content-Type'    = 'application/json; charset=utf-8'
            'Idempotency-Key' = $eventId
        }
        $bodyBytes = Get-SacUtf8Bytes -Text $jsonText
        $resp = Invoke-WebRequest -Uri $ingest -Method Post -Headers $headers -Body $bodyBytes -UseBasicParsing -TimeoutSec $timeout
        if (Test-SacIngestAcceptedStatus -StatusCode $resp.StatusCode) {
            Complete-SacIngestSuccess -EventId $eventId -EventType $eventType -StatusCode $resp.StatusCode
            return $true
        }
        $body = if ($resp.Content) { $resp.Content } else { '' }
        if ($resp.StatusCode -eq 422) {
            $spoolOnFailure = $false
            Write-SacLog "WARN: SAC POST HTTP 422 validation (not spooled) type=$eventType event_id=$eventId"
            Write-SacPostBodyDiagnostic -BodyBytes $bodyBytes -EventId $eventId
        }
        if ($body.Length -gt 0) {
            $snippet = $body.Substring(0, [Math]::Min(800, $body.Length))
            Write-SacLog "WARN: SAC POST HTTP $($resp.StatusCode): $snippet"
        } else {
            Write-SacLog "WARN: SAC POST HTTP $($resp.StatusCode) (empty body)"
        }
    } catch {
        $code = 0
        $body = Get-SacHttpErrorBody -ErrorRecord $_
        if ($_.Exception.Response) {
            $code = [int]$_.Exception.Response.StatusCode
        }
        if (Test-SacIngestAcceptedStatus -StatusCode $code) {
            Complete-SacIngestSuccess -EventId $eventId -EventType $eventType -StatusCode $code
            return $true
        }
        if ($code -eq 422) {
            $spoolOnFailure = $false
            Write-SacLog "WARN: SAC POST HTTP 422 validation (not spooled) type=$eventType event_id=$eventId"
            Write-SacPostBodyDiagnostic -BodyBytes $bodyBytes -EventId $eventId
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

    Write-SacSpoolFile -EventId $eventId -JsonBody $jsonText
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

    $payload = $(New-SacEventPayload -EventType $EventType -Severity $Severity -Title $Title -Summary $Summary -Details $Details)
    if ($payload -is [System.Array]) {
        $payload = $payload[-1]
    }
    $json = $(ConvertTo-SacJsonText -Payload $payload)
    $json = Repair-SacJsonText -Text (Get-SacSingleString -Value $json -Label 'event json')
    if ([string]::IsNullOrWhiteSpace($json) -or $json[0] -ne '{') {
        Write-SacLog "WARN: SAC invalid JSON for type=$EventType (empty or does not start with {{)"
        return $false
    }
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
