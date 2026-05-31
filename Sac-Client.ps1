<#
.SYNOPSIS
    Клиент Security Alert Center для RDP-login-monitor.
.DESCRIPTION
    Dot-source после login_monitor.settings.ps1 и функции Write-Log.
    Ожидает: $UseSAC, $SacUrl, $SacApiKey, $ScriptVersion, $script:InstallRoot.
    Release: same as Login_Monitor.ps1 $ScriptVersion / version.txt (host.display_name via $ServerDisplayName).
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

function Get-SacHostBlock {
    $hostname = [string]$env:COMPUTERNAME
    $hostBlock = [ordered]@{
        hostname  = $hostname
        os_family = 'windows'
    }
    if (Get-Variable -Name ServerDisplayName -ErrorAction SilentlyContinue) {
        $label = (Get-Variable -Name ServerDisplayName -ValueOnly)
        if (-not [string]::IsNullOrWhiteSpace([string]$label)) {
            $hostBlock.display_name = [string]$label.Trim()
        }
    }
    $ipv4 = Get-SacHostIPv4
    if (-not [string]::IsNullOrWhiteSpace($ipv4)) {
        $hostBlock.ipv4 = $ipv4
    }
    return $hostBlock
}

function Get-SacHostIPv4 {
    # Явный override в login_monitor.settings.ps1 (опционально).
    if (Get-Variable -Name ServerIPv4 -ErrorAction SilentlyContinue) {
        $manual = [string](Get-Variable -Name ServerIPv4 -ValueOnly)
        if (-not [string]::IsNullOrWhiteSpace($manual)) {
            $m = $manual.Trim()
            if ($m -match '^(?:\d{1,3}\.){3}\d{1,3}$') { return $m }
            Write-SacLog "WARN: ServerIPv4='$m' не похож на IPv4, игнорирую override"
        }
    }

    try {
        $ips = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
            $_.IPAddress -and
            $_.IPAddress -notmatch '^(127\.|169\.254\.)' -and
            $_.PrefixOrigin -ne 'WellKnown'
        } | Select-Object -ExpandProperty IPAddress)
        if ($ips.Count -gt 0) { return [string]$ips[0] }
    } catch {}

    try {
        $sock = New-Object System.Net.Sockets.Socket ([System.Net.Sockets.AddressFamily]::InterNetwork), ([System.Net.Sockets.SocketType]::Dgram), ([System.Net.Sockets.ProtocolType]::Udp)
        $sock.Connect('1.1.1.1', 53)
        $ip = [string]$sock.LocalEndPoint.Address
        $sock.Dispose()
        if ($ip -match '^(?:\d{1,3}\.){3}\d{1,3}$' -and $ip -notmatch '^(127\.|169\.254\.)') { return $ip }
    } catch {}

    return ''
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
        host           = (Get-SacHostBlock)
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

function Get-SacPostBodyBytes {
    param([string]$JsonText)
    $bytes = Get-SacUtf8Bytes -Text $JsonText
    if ($bytes -is [System.Array] -and $bytes -isnot [byte[]]) {
        $flat = New-Object System.Collections.Generic.List[byte]
        foreach ($chunk in $bytes) {
            if ($null -eq $chunk) { continue }
            if ($chunk -is [byte[]]) {
                foreach ($b in $chunk) { $flat.Add($b) | Out-Null }
            } elseif ($chunk -is [byte]) {
                $flat.Add([byte]$chunk) | Out-Null
            }
        }
        $bytes = $flat.ToArray()
    }
    if ($bytes -isnot [byte[]]) {
        Write-SacLog "WARN: SAC POST aborted: body is not byte[] (type=$($bytes.GetType().FullName))"
        return $null
    }
    if ($bytes.Length -ge 4 -and $bytes[0] -eq 0x6E -and $bytes[1] -eq 0x75 -and $bytes[2] -eq 0x6C -and $bytes[3] -eq 0x6C) {
        Write-SacLog 'WARN: SAC POST aborted: body starts with ASCII null (0x6E756C6C)'
        return $null
    }
    if ($bytes.Length -lt 2 -or $bytes[0] -ne 0x7B) {
        $take = [Math]::Min(16, $bytes.Length)
        $hex = if ($take -gt 0) {
            (($bytes[0..($take - 1)] | ForEach-Object { '{0:X2}' -f $_ }) -join ' ')
        } else { '(empty)' }
        Write-SacLog "WARN: SAC POST aborted: body must start with 0x7B '{{' (hex: $hex)"
        return $null
    }
    try {
        $text = [System.Text.Encoding]::UTF8.GetString($bytes)
        Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
        $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
        $null = $ser.DeserializeObject($text)
    } catch {
        Write-SacLog "WARN: SAC POST aborted: local JSON parse failed ($($_.Exception.Message))"
        return $null
    }
    return $bytes
}

function Invoke-SacHttpPost {
    param(
        [string]$Uri,
        [byte[]]$BodyBytes,
        [string]$EventId,
        [int]$TimeoutSec
    )
    Invoke-SacTlsPrep
    $req = [System.Net.HttpWebRequest]::Create($Uri)
    $req.Method = 'POST'
    $req.Timeout = $TimeoutSec * 1000
    $req.ReadWriteTimeout = $TimeoutSec * 1000
    $req.ContentType = 'application/json'
    $req.ContentLength = $BodyBytes.Length
    $req.Headers[[System.Net.HttpRequestHeader]::Authorization] = "Bearer $SacApiKey"
    $req.Headers.Add('Idempotency-Key', $EventId)

    $stream = $req.GetRequestStream()
    try {
        $stream.Write($BodyBytes, 0, $BodyBytes.Length)
    } finally {
        $stream.Close()
    }

    try {
        $resp = $req.GetResponse()
        $code = [int]$resp.StatusCode
        $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
        $content = $reader.ReadToEnd()
        $reader.Close()
        $resp.Close()
        return @{ StatusCode = $code; Content = $content }
    } catch [System.Net.WebException] {
        $code = 0
        $content = ''
        $exResp = $_.Exception.Response
        if ($null -ne $exResp) {
            $code = [int]$exResp.StatusCode
            try {
                $reader = New-Object System.IO.StreamReader($exResp.GetResponseStream())
                $content = $reader.ReadToEnd()
                $reader.Close()
            } catch { }
            $exResp.Close()
        }
        return @{ StatusCode = $code; Content = $content; Error = $_.Exception.Message }
    }
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
    $bodyBytes = $null

    $bodyBytes = Get-SacPostBodyBytes -JsonText $jsonText
    if ($null -eq $bodyBytes) {
        Move-SacSpoolToRejected -EventId $eventId
        return $false
    }

    $post = Invoke-SacHttpPost -Uri $ingest -BodyBytes $bodyBytes -EventId $eventId -TimeoutSec $timeout
    $code = [int]$post.StatusCode
    $body = if ($post.Content) { [string]$post.Content } else { '' }

    if (Test-SacIngestAcceptedStatus -StatusCode $code) {
        Complete-SacIngestSuccess -EventId $eventId -EventType $eventType -StatusCode $code
        return $true
    }

    if ($code -eq 422) {
        $spoolOnFailure = $false
        Write-SacLog "WARN: SAC POST HTTP 422 validation (not spooled) type=$eventType event_id=$eventId len=$($bodyBytes.Length)"
        Write-SacPostBodyDiagnostic -BodyBytes $bodyBytes -EventId $eventId
    } elseif ($code -gt 0) {
        Write-SacLog "WARN: SAC POST HTTP $code type=$eventType event_id=$eventId len=$($bodyBytes.Length)"
    } elseif (-not [string]::IsNullOrWhiteSpace($post.Error)) {
        Write-SacLog "WARN: SAC POST failed type=$eventType event_id=${eventId}: $($post.Error)"
    }

    if ($body.Length -gt 0) {
        $snippet = $body.Substring(0, [Math]::Min(800, $body.Length))
        Write-SacLog "WARN: SAC POST response: $snippet"
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

    $mergedDetails = @{}
    if ($null -ne $Details) {
        foreach ($k in $Details.Keys) {
            $mergedDetails[$k] = $Details[$k]
        }
    }
    if (-not $mergedDetails.ContainsKey('generated_by')) {
        $mergedDetails['generated_by'] = 'agent'
    }

    $payload = $(New-SacEventPayload -EventType $EventType -Severity $Severity -Title $Title -Summary $Summary -Details $mergedDetails)
    if ($payload -is [System.Array]) {
        $payload = $payload[-1]
    }
    $json = $(ConvertTo-SacJsonText -Payload $payload)
    $json = Repair-SacJsonText -Text (Get-SacSingleString -Value $json -Label 'event json')
    if ([string]::IsNullOrWhiteSpace($json) -or $json[0] -ne '{') {
        Write-SacLog "WARN: SAC invalid JSON for type=$EventType (empty or does not start with '{' )"
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
