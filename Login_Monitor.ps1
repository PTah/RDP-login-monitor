<#
.SYNOPSIS
  Windows login / RDP / RD Gateway event monitor; Telegram notifications.
.DESCRIPTION
  Watches Security 4624/4625, optional Microsoft-Windows-TerminalServices-Gateway/Operational
  302/303, log rotation, heartbeat file, and daily report.
.NOTES
  PowerShell 5.0+; run elevated. String literals in this file are kept ASCII-only so the script
  still parses if the .ps1 was re-encoded during download (e.g. broken UTF-8). Telegram messages are English.
#>

[CmdletBinding()]
param(
    [string]$TelegramBotToken = "<TELEGRAM_BOT_TOKEN>",
    [string]$TelegramChatID = "<TELEGRAM_CHAT_ID>"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# RU auditpol labels as BMP code points (ASCII-only source)
function Uc { param([int[]]$C) -join ($C | ForEach-Object { [char]$_ }) }

# ============================================
# CONFIG
# ============================================

# Version; logged to file and host on start
$ScriptVersion = "1.2.0"

# Logs
$LogFile = "D:\Soft\Logs\login_monitor.log"
$LogBackupFolder = "D:\Soft\Logs\Backup"
$MaxBackupDays = 30

# Log rotation (daily at local time)
$LogRotationHour = 0
$LogRotationMinute = 0

# Heartbeat file only (no Telegram)
$HeartbeatInterval = 3600
$HeartbeatFile = "D:\Soft\Logs\last_heartbeat.txt"

# Daily report (local time)
$DailyReportHour = 9
$DailyReportMinute = 0
$LastReportFile = "D:\Soft\Logs\last_daily_report.txt"

# RD Gateway
$EnableRDGatewayMonitoring = $true
$RDGatewayLogName = "Microsoft-Windows-TerminalServices-Gateway/Operational"
$RDGatewayEvents = @(302, 303)

$ExcludedProcesses = @(
    "HTTP", "HTTP/*", "W3WP.EXE", "MSExchange", "SYSTEM", "LOCAL SERVICE",
    "NETWORK SERVICE", "OUTLOOK.EXE", "EXCHANGE", "EDGETRANSPORT", "STORE.EXE",
    "MAD.EXE", "UMservice", "MSExchangeADTopology", "MSExchangeAntispam",
    "MSExchangeDelivery", "MSExchangeFrontendTransport", "MSExchangeHM",
    "MSExchangeMailboxAssistants", "MSExchangeMailboxReplication", "MSExchangeRPC",
    "MSExchangeSubmission", "MSExchangeThrottling", "MSExchangeTransport",
    "MSExchangeTransportLogSearch", "IIS", "SQLSERVR.EXE", "MSSQL$",
    "WINLOGON.EXE", "LSASS.EXE", "SVCHOST.EXE",
    "%%2310",
    "%%2313"
)

$ExcludedUsers = @(
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON"
)

$ExcludedUserPatterns = @(
    "HealthMailbox*",
    "DWM-*",
    "UMFD-*",
    "Font Driver Host*"
)

$ExcludedLogonProcesses = @(
    "NtLmSsp"
)

$ExcludedComputerPatterns = @(
    "00000000-0000-0000-0000-000000000000",
    "*-*-*-*-*",
    "NT AUTHORITY",
    "NtLmSsp",
    "NtLmSsp*",
    "Authz",
    "Authz*"
)

# Optional: ignore noisy network logon (type 3) from a specific source IP + logon process substring
# (e.g. some LDAP / mail gateway sync tools)
$IgnoreAdvapiNetworkLogonSourceIps = @(
    "192.168.160.57"
)
$IgnoreAdvapiNetworkLogonProcessContains = "Advapi"

# ============================================
# INIT
# ============================================

$LogDir = Split-Path $LogFile -Parent
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
if (!(Test-Path $LogBackupFolder)) { New-Item -ItemType Directory -Path $LogBackupFolder -Force | Out-Null }

# UTF-8 with BOM for log files (safer in older viewers)
$script:Utf8BomEncoding = New-Object System.Text.UTF8Encoding $true

function Ensure-FileStartsWithUtf8Bom {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) { return }
    $bom = [byte[]](0xEF, 0xBB, 0xBF)
    $combined = New-Object byte[] ($bom.Length + $bytes.Length)
    [Buffer]::BlockCopy($bom, 0, $combined, 0, $bom.Length)
    if ($bytes.Length -gt 0) {
        [Buffer]::BlockCopy($bytes, 0, $combined, $bom.Length, $bytes.Length)
    }
    [System.IO.File]::WriteAllBytes($Path, $combined)
}

function Write-TextFileUtf8Bom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text
    )
    [System.IO.File]::WriteAllText($Path, $Text, $script:Utf8BomEncoding)
}

Ensure-FileStartsWithUtf8Bom -Path $LogFile

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $Message" + [Environment]::NewLine
    [System.IO.File]::AppendAllText($LogFile, $logMessage, $script:Utf8BomEncoding)
    Write-Host ($logMessage.TrimEnd("`r`n"))
}

function ConvertTo-TelegramHtml {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

try {
    [System.Net.ServicePointManager]::SecurityProtocol =
        [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
    Write-Log "TLS 1.2 enabled"
} catch {
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        Write-Log "TLS 1.2 set"
    } catch {
        Write-Log "WARNING: could not set TLS 1.2"
    }
}

function Send-TelegramMessage {
    param([string]$Message)

    if ([string]::IsNullOrWhiteSpace($TelegramBotToken) -or [string]::IsNullOrWhiteSpace($TelegramChatID)) {
        Write-Log "Telegram: missing token or chat_id"
        return $false
    }

    $uri = "https://api.telegram.org/bot$TelegramBotToken/sendMessage"
    $body = @{
        chat_id = $TelegramChatID
        text = $Message
        parse_mode = "HTML"
    }

    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        $null = Invoke-RestMethod -Uri $uri -Method Post -Body $body -ErrorAction Stop -TimeoutSec 30
        return $true
    } catch {
        Write-Log "Telegram send error: $($_.Exception.Message)"
        return $false
    }
}

function Test-TelegramConnection {
    Write-Log "Testing Telegram API (getMe)..."
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        $testUrl = "https://api.telegram.org/bot$TelegramBotToken/getMe"
        $response = Invoke-RestMethod -Uri $testUrl -Method Get -TimeoutSec 10 -ErrorAction Stop
        if ($response.ok) {
            Write-Log "Telegram OK, bot: @$($response.result.username)"
            return $true
        }
    } catch {
        Write-Log "Telegram API error: $($_.Exception.Message)"
        return $false
    }
    return $false
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    Write-Log "ERROR: run elevated (Administrator). Version $ScriptVersion"
    exit 1
}
Write-Log "Running as Administrator, version $ScriptVersion"

function Enable-SecurityAudit {
    Write-Log "Checking security audit (auditpol) settings..."

    # auditpol writes to stderr; do not throw under $ErrorActionPreference = Stop.
    function Invoke-AuditPol {
        param([Parameter(Mandatory = $true)][string]$Arguments)
        $cmd = "auditpol $Arguments 2>&1"
        $text = cmd.exe /c $cmd
        $code = $LASTEXITCODE
        return [pscustomobject]@{
            ExitCode = $code
            Text = ($text | Out-String).Trim()
        }
    }

    function Test-RussianUiPreferred {
        try {
            if ((Get-Culture).TwoLetterISOLanguageName -eq 'ru') { return $true }
        } catch { }

        if ($PSUICulture -like 'ru*') { return $true }

        $r = Invoke-AuditPol -Arguments '/list /subcategory:*'
        if ($r.ExitCode -ne 0) { return $false }
        $ax = Uc @(0x0412,0x0445,0x043E,0x0434,0x002F,0x0432,0x044B,0x043E,0x0434)
        return ($r.Text -like ('*{0}*' -f $ax))
    }

    function Test-SuccessAndFailureText {
        param([string]$Line)
        if ([string]::IsNullOrWhiteSpace($Line)) { return $false }
        $w1 = Uc @(0x0443,0x0441,0x043F,0x0435,0x0445)
        $w2 = Uc @(0x0438)
        $w3 = Uc @(0x0441,0x0431,0x043E,0x0439)
        $p1 = '(?i)' + [regex]::Escape($w1) + '\s+' + [regex]::Escape($w2) + '\s+' + [regex]::Escape($w3)
        $p2 = '(?i)' + [regex]::Escape($w1) + '\s*' + [regex]::Escape($w2) + '\s*' + [regex]::Escape($w3)
        if ($Line -match $p1) { return $true }
        if ($Line -match $p2) { return $true }
        if (($Line -match '(?i)Success') -and ($Line -match '(?i)Failure')) { return $true }
        return $false
    }

    function Get-CategorySettingLine {
        param(
            [Parameter(Mandatory = $true)][string]$CategoryName,
            [Parameter(Mandatory = $true)][string]$SubcategoryLabel
        )
        $r = Invoke-AuditPol -Arguments ('/get /category:"{0}"' -f $CategoryName)
        if ($r.ExitCode -ne 0) {
            return [pscustomobject]@{ Ok = $false; ExitCode = $r.ExitCode; Text = $r.Text; Line = $null }
        }

        $lines = $r.Text -split "`r?`n"
        foreach ($ln in $lines) {
            $t = ($ln -replace '\s+', ' ').Trim()
            if ([string]::IsNullOrWhiteSpace($t)) { continue }

            if ($t -notlike ('*{0}*' -f $SubcategoryLabel)) { continue }
            return [pscustomobject]@{ Ok = $true; ExitCode = 0; Text = $r.Text; Line = $t }
        }

        return [pscustomobject]@{ Ok = $true; ExitCode = 0; Text = $r.Text; Line = $null }
    }

    function Ensure-RuLogonLogoffSubcategories {
        $category = Uc @(0x0412,0x0445,0x043E,0x0434,0x002F,0x0432,0x044B,0x043E,0x0434)
        $targets = @(
            (Uc @(0x0412,0x0445,0x043E,0x0434,0x0020,0x0432,0x0020,0x0441,0x0438,0x0441,0x0442,0x0435,0x043C,0x0443)),
            (Uc @(0x0412,0x044B,0x0445,0x043E,0x0434,0x0020,0x0438,0x0437,0x0020,0x0441,0x0438,0x0441,0x0442,0x0435,0x043C,0x044B))
        )

        foreach ($sub in $targets) {
            $cur = Get-CategorySettingLine -CategoryName $category -SubcategoryLabel $sub
            if (-not $cur.Ok) {
                Write-Log ("Failed auditpol /get /category for category '{0}' (exit {1}). Output:`n{2}" -f $category, $cur.ExitCode, $cur.Text)
                return $false
            }

            if ($null -eq $cur.Line) {
                $frag = $cur.Text
                if ($frag.Length -gt 4000) { $frag = $frag.Substring(0, 4000) + "`n... (truncated)" }
                Write-Log ("Category '{0}': no line containing subcategory '{1}'. Output (excerpt):`n{2}" -f $category, $sub, $frag)
                return $false
            }

            if (Test-SuccessAndFailureText -Line $cur.Line) {
                Write-Log ("Subcategory {0} already has Success+Failure. Line: {1}" -f $sub, $cur.Line)
                continue
            }

            Write-Log ("Enabling Success+Failure for subcategory: {0}. Current line: {1}" -f $sub, $cur.Line)
            $setArgs = ('/set /subcategory:"{0}" /success:enable /failure:enable' -f $sub)
            $set = Invoke-AuditPol -Arguments $setArgs
            if ($set.ExitCode -ne 0) {
                Write-Log ("auditpol SET FAIL (code {0}): {1}`n{2}" -f $set.ExitCode, $setArgs, $set.Text)
                return $false
            }

            $after = Get-CategorySettingLine -CategoryName $category -SubcategoryLabel $sub
            if ($null -ne $after.Line -and (Test-SuccessAndFailureText -Line $after.Line)) {
                Write-Log ("OK: subcategory {0} set to Success+Failure. Line: {1}" -f $sub, $after.Line)
            } else {
                Write-Log ("After SET, line for {0} is still not Success+Failure. Line: {1}" -f $sub, $after.Line)
                return $false
            }
        }

        return $true
    }

    function Ensure-EnLogonLogoffSubcategories {
        $category = "Logon/Logoff"
        $targets = @("Logon", "Logoff")
        foreach ($sub in $targets) {
            $cur = Get-CategorySettingLine -CategoryName $category -SubcategoryLabel $sub
            if (-not $cur.Ok) {
                Write-Log ("Failed auditpol /get /category for category '{0}' (exit {1}). Output:`n{2}" -f $category, $cur.ExitCode, $cur.Text)
                return $false
            }
            if ($null -eq $cur.Line) {
                Write-Log ("In category '{0}': no line for subcategory '{1}'." -f $category, $sub)
                return $false
            }
            if (Test-SuccessAndFailureText -Line $cur.Line) { continue }

            $setArgs = ('/set /subcategory:"{0}" /success:enable /failure:enable' -f $sub)
            $set = Invoke-AuditPol -Arguments $setArgs
            if ($set.ExitCode -ne 0) {
                Write-Log ("auditpol SET FAIL (code {0}): {1}`n{2}" -f $set.ExitCode, $setArgs, $set.Text)
                return $false
            }
        }
        return $true
    }

    $preferRu = Test-RussianUiPreferred

    if ($preferRu) {
        if (Ensure-RuLogonLogoffSubcategories) {
            Write-Log "Audit policy (RU): enabled for Russian subcategory names (Logon/Logoff / Russian UI output)."
            return
        }

        Write-Log "WARNING (RU): could not set Russian Advanced Audit subcategories through auditpol. The script will continue, but some events may be missing. Check domain/GPO (central Advanced Audit Policy may override)."
        return
    }

    if (Ensure-EnLogonLogoffSubcategories) {
        Write-Log "Audit policy (EN): OK for Logon/Logoff (English UI output)."
        return
    }

    # Logon/Logoff category GUID (not a user id).
    Write-Log "Trying Logon/Logoff category set via known GUID (fallback)..."
    $guidSet = Invoke-AuditPol -Arguments '/set /category:"{69979849-797A-11D9-BED3-505054503030}" /success:enable /failure:enable'
    if ($guidSet.ExitCode -ne 0) {
        Write-Log ("auditpol GUID SET FAIL (code {0}):`n{1}" -f $guidSet.ExitCode, $guidSet.Text)
    }

    Write-Log "WARNING: could not configure logon/logoff auditing via auditpol automatically. The script will continue; check audit policy in local/domain GPO."
}

function Test-RDSDeploymentPresent {
    # Gateway-only nodes are not "full session host"; gateway traffic uses separate Telegram lines (302/303)
    $gatewayOnlyFeatureNames = @('RDS-Gateway', 'RDS-WEB-ACCESS')

    try {
        if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
            $rdsFeatures = @(Get-WindowsFeature -ErrorAction SilentlyContinue | Where-Object {
                $_.Name -like 'RDS*' -and $_.InstallState -eq 'Installed'
            })
            $sessionOrHostLike = @($rdsFeatures | Where-Object { $gatewayOnlyFeatureNames -notcontains $_.Name })
            if ($sessionOrHostLike.Count -gt 0) {
                return $true
            }
        }
    } catch { }

    try {
        if (Get-Service -Name 'UmRdpService' -ErrorAction SilentlyContinue) {
            return $true
        }
    } catch { }

    return $false
}

function Send-Heartbeat {
    param([switch]$IsStartup = $false)

    $timestamp = Get-Date -Format "dd.MM.yyyy HH:mm:ss"
    $hHost = (ConvertTo-TelegramHtml $env:COMPUTERNAME)

    if ($IsStartup) {
        $message = "<b>Login monitor started</b>`r`n"
        $message += "Host: $hHost`r`n"
        $message += "Time: $timestamp"
        if (Test-RDSDeploymentPresent) {
            $message += "`r`n<b>RDS (session host role):</b> this server has non-Gateway RDS components; 4624/4625 and configured logon types are monitored (see script settings)"
        }
        if ($EnableRDGatewayMonitoring) {
            try {
                $gwLog = Get-WinEvent -ListLog $RDGatewayLogName -ErrorAction SilentlyContinue
                if ($gwLog) {
                    $message += "`r`n<b>RD Gateway log:</b> also recording user connections to <b>internal target PCs</b> via the gateway (events 302/303)"
                }
            } catch { }
        }
        Send-TelegramMessage -Message $message | Out-Null
        Write-Log "Startup notification sent to Telegram"
    } else {
        Write-TextFileUtf8Bom -Path $HeartbeatFile -Text $timestamp
    }
}

function Send-StopNotification {
    param([string]$Reason)

    $timestamp = Get-Date -Format "dd.MM.yyyy HH:mm:ss"
    $hHost = (ConvertTo-TelegramHtml $env:COMPUTERNAME)
    $hReason = (ConvertTo-TelegramHtml $Reason)
    $message = "<b>Login monitor stopped</b>`r`n"
    $message += "Host: $hHost`r`n"
    $message += "Time: $timestamp`r`n"
    $message += "Reason: $hReason"

    Send-TelegramMessage -Message $message | Out-Null
    Write-Log "Stop notification sent: $Reason"
}

function Rotate-LogFile {
    try {
        if (Test-Path $LogFile) {
            $backupDate = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
            $backupFileName = "LoginLog_$backupDate.bak"
            $backupFilePath = Join-Path $LogBackupFolder $backupFileName

            Copy-Item -Path $LogFile -Destination $backupFilePath -Force
            Clear-Content -Path $LogFile -Force
            # Re-add UTF-8 BOM after Clear-Content
            Ensure-FileStartsWithUtf8Bom -Path $LogFile
            Write-Log "Log file copied to backup: $backupFilePath"

            $oldBackups = Get-ChildItem -Path $LogBackupFolder -Filter "LoginLog_*.bak" |
                Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$MaxBackupDays) }

            foreach ($oldBackup in $oldBackups) {
                Remove-Item -Path $oldBackup.FullName -Force
                Write-Log "Deleted old backup: $($oldBackup.Name)"
            }
            return $true
        }
    } catch {
        Write-Log "Log rotation error: $($_.Exception.Message)"
    }
    return $false
}

function Get-NextLocalSlotBoundary {
    param(
        [int]$Hour,
        [int]$Minute
    )
    $now = Get-Date
    $slotToday = Get-Date -Year $now.Year -Month $now.Month -Day $now.Day -Hour $Hour -Minute $Minute -Second 0
    if ($now -lt $slotToday) { return $slotToday }
    return $slotToday.AddDays(1)
}

function Get-MostRecentRotationSlot {
    $now = Get-Date
    $slotToday = Get-Date -Year $now.Year -Month $now.Month -Day $now.Day -Hour $LogRotationHour -Minute $LogRotationMinute -Second 0
    if ($now -ge $slotToday) { return $slotToday }
    return $slotToday.AddDays(-1)
}

function Check-AndRotateLog {
    $lastRotationFile = Join-Path $LogBackupFolder "last_rotation.txt"
    $lastRotation = $null

    if (Test-Path $lastRotationFile) {
        $lastRotationRaw = Get-Content $lastRotationFile -ErrorAction SilentlyContinue
        if ($lastRotationRaw) {
            $lastRotation = [datetime]::ParseExact($lastRotationRaw, "yyyy-MM-dd HH:mm:ss", $null)
        }
    }

    $currentTime = Get-Date
    $mostRecentSlot = Get-MostRecentRotationSlot
    $shouldRotate = $false
    if ($null -eq $lastRotation) { $shouldRotate = $true }
    elseif ($lastRotation -lt $mostRecentSlot) { $shouldRotate = $true }

    if ($shouldRotate -and (Rotate-LogFile)) {
        Write-TextFileUtf8Bom -Path $lastRotationFile -Text ($currentTime.ToString("yyyy-MM-dd HH:mm:ss"))
    }
    return (Get-NextLocalSlotBoundary -Hour $LogRotationHour -Minute $LogRotationMinute)
}

function Cleanup-OldLogs {
    try {
        if (Test-Path $LogBackupFolder) {
            $oldBackups = Get-ChildItem -Path $LogBackupFolder -Filter "LoginLog_*.bak" |
                Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$MaxBackupDays) }
            foreach ($oldBackup in $oldBackups) {
                Remove-Item -Path $oldBackup.FullName -Force
                Write-Log "Deleted old backup: $($oldBackup.Name)"
            }
        }
    } catch {
        Write-Log "Old log cleanup error: $($_.Exception.Message)"
    }
}

function Get-EventDataMap {
    param($Event)
    $map = @{}
    try {
        $xml = [xml]$Event.ToXml()
        foreach ($d in $xml.Event.EventData.Data) {
            $name = [string]$d.Name
            if ([string]::IsNullOrWhiteSpace($name)) { continue }
            $map[$name] = [string]$d.'#text'
        }
    } catch { }
    return $map
}

function Get-FirstNonEmptyMapValue {
    param([hashtable]$DataMap, [string[]]$Keys)
    foreach ($k in $Keys) {
        if (-not $DataMap.ContainsKey($k)) { continue }
        $v = $DataMap[$k]
        if (-not [string]::IsNullOrWhiteSpace($v)) { return [string]$v }
    }
    return $null
}

function Convert-ToIntSafe {
    param([object]$Value)
    if ($null -eq $Value) { return 0 }
    $s = [string]$Value
    if ($s -match '(\d+)') { return [int]$Matches[1] }
    return 0
}

function Get-LogonTypeName {
    param([int]$LogonType)
    switch ($LogonType) {
        2  { return "Interactive (console) (2)" }
        3  { return "Network (3) / often RDP on some hosts" }
        10 { return "Remote interactive RDP (10)" }
        4  { return "Batch (4)" }
        5  { return "Service (5)" }
        7  { return "Unlock (7)" }
        8  { return "Network cleartext (8)" }
        9  { return "New credentials (9)" }
        default { return "Type $LogonType (other)" }
    }
}

function Should-IgnoreEvent {
    param(
        [string]$Username,
        [string]$ProcessName,
        [string]$ComputerName,
        [int]$EventID,
        [int]$LogonType = 0,
        [string]$SourceIP = ""
    )

    if ($null -ne $Username)     { $Username = $Username.Trim() }
    if ($null -ne $ComputerName) { $ComputerName = $ComputerName.Trim() }
    if ($null -ne $ProcessName)  { $ProcessName = $ProcessName.Trim() }
    if ($null -ne $SourceIP)     { $SourceIP = $SourceIP.Trim() }

    if ($EventID -eq 4648) { return $true }
    if ([string]::IsNullOrWhiteSpace($Username)) { return $true }

    # DWM/UMFD (e.g. DOMAIN\\DWM-8)
    if ($Username -match '(?i)(\\)?DWM-\d+') { return $true }
    if ($Username -match '(?i)(\\)?UMFD-\d+') { return $true }
    if ($Username -like "*$") { return $true }

    # Network logon 3 + Advapi + allowlisted source IP
    if ($EventID -eq 4624 -and $LogonType -eq 3) {
        foreach ($ip in $IgnoreAdvapiNetworkLogonSourceIps) {
            if ([string]::IsNullOrWhiteSpace($ip)) { continue }
            if ($SourceIP -eq $ip -and $ProcessName -like ("*{0}*" -f $IgnoreAdvapiNetworkLogonProcessContains)) {
                return $true
            }
        }
    }

    foreach ($excludedUser in $ExcludedUsers) {
        if ($Username -like "*$excludedUser*") { return $true }
    }
    foreach ($p in $ExcludedUserPatterns) {
        if ($Username -like $p) { return $true }
    }

    if ($ComputerName -eq "Authz" -or $ComputerName -like "Authz*") { return $true }
    if ($ComputerName -eq "NtLmSsp" -or $ComputerName -like "NtLmSsp*" -or $ComputerName -like "*NtLmSsp*") { return $true }

    foreach ($lp in $ExcludedLogonProcesses) {
        if ($ProcessName -like "*$lp*") { return $true }
    }
    foreach ($excludedProcess in $ExcludedProcesses) {
        if ($ProcessName -like "*$excludedProcess*") { return $true }
    }

    if ($SourceIP -eq "127.0.0.1" -or $SourceIP -like "fe80:*") { return $true }
    if ($ComputerName -eq "-" -or $ComputerName -eq "N/A") { return $true }

    foreach ($pattern in $ExcludedComputerPatterns) {
        if ($ComputerName -like $pattern) { return $true }
    }

    return $false
}

function Get-LoginEventInfo {
    param($Event)

    $eventData = @{
        TimeCreated = $Event.TimeCreated
        Username = "-"
        ComputerName = "-"
        SourceIP = "-"
        ProcessName = "-"
        LogonType = 0
    }

    try {
        $map = Get-EventDataMap -Event $Event
        $eventData.Username = Get-FirstNonEmptyMapValue -DataMap $map -Keys @("TargetUserName","AccountName","UserName","SubjectUserName")
        $eventData.ComputerName = Get-FirstNonEmptyMapValue -DataMap $map -Keys @("WorkstationName","ComputerName","TargetWorkstationName")
        $eventData.SourceIP = Get-FirstNonEmptyMapValue -DataMap $map -Keys @("IpAddress","SourceNetworkAddress","Ip")
        $eventData.LogonType = Convert-ToIntSafe (Get-FirstNonEmptyMapValue -DataMap $map -Keys @("LogonType"))

        if ($Event.Id -eq 4624) {
            $eventData.ProcessName = Get-FirstNonEmptyMapValue -DataMap $map -Keys @(
                "LogonProcessName","AuthenticationPackageName","AuthenticationPackage","ProcessName"
            )
        } elseif ($Event.Id -eq 4625) {
            $eventData.ProcessName = Get-FirstNonEmptyMapValue -DataMap $map -Keys @(
                "SubStatus","Status","FailureReason","FailureReasonCode"
            )
        }
    } catch {
        Write-Log "Error parsing event data: $($_.Exception.Message)"
    }

    if ([string]::IsNullOrWhiteSpace($eventData.Username)) { $eventData.Username = "-" }
    if ([string]::IsNullOrWhiteSpace($eventData.ComputerName)) { $eventData.ComputerName = "-" }
    if ([string]::IsNullOrWhiteSpace($eventData.SourceIP)) { $eventData.SourceIP = "-" }
    if ([string]::IsNullOrWhiteSpace($eventData.ProcessName)) { $eventData.ProcessName = "-" }

    return $eventData
}

function Format-LoginEvent {
    param(
        [int]$EventID,
        [string]$Username,
        [string]$ComputerName,
        [string]$SourceIP,
        [string]$ProcessName,
        [datetime]$TimeCreated,
        [int]$LogonType,
        [string]$LogonTypeName,
        [string]$SecurityLogComputerName
    )

    $logHost = $SecurityLogComputerName
    if ([string]::IsNullOrWhiteSpace($logHost)) { $logHost = $env:COMPUTERNAME }
    $hUser = (ConvertTo-TelegramHtml $Username)
    $hLog = (ConvertTo-TelegramHtml $logHost)
    $hWkst = (ConvertTo-TelegramHtml $ComputerName)
    $hIp = (ConvertTo-TelegramHtml $SourceIP)
    $hProc = (ConvertTo-TelegramHtml $ProcessName)
    $hLtName = (ConvertTo-TelegramHtml $LogonTypeName)
    $hTime = (ConvertTo-TelegramHtml ($TimeCreated.ToString('dd.MM.yyyy HH:mm:ss')))

    $message = "<b>"
    if ($EventID -eq 4624) { $message += "LOGON OK" }
    elseif ($EventID -eq 4625) { $message += "LOGON FAILED" }
    else { $message += "EVENT" }
    $message += "</b>`r`n"

    $message += "User: $hUser`r`n"
    $message += "Security log (machine): $hLog`r`n"
    $message += "Workstation: $hWkst`r`n"
    $message += "IP: $hIp`r`n"
    $message += "Process/code: $hProc`r`n"
    $message += "Logon type: $hLtName ($LogonType)`r`n"
    $message += "Time: $hTime`r`n"
    $message += "Event ID: $EventID"

    return $message
}

function Test-RDGatewayLog {
    try {
        $logExists = Get-WinEvent -ListLog $RDGatewayLogName -ErrorAction SilentlyContinue
        if ($logExists) {
            Write-Log "RD Gateway log found: $RDGatewayLogName"
            return $true
        }
    } catch {
        Write-Log "RD Gateway log check error: $($_.Exception.Message)"
    }
    return $false
}

function Get-RDGatewayEventInfo {
    param($Event)
    $eventData = @{
        TimeCreated = $Event.TimeCreated
        Username = "N/A"
        ExternalIP = "N/A"
        InternalIP = "N/A"
        Protocol = "N/A"
        ErrorCode = "N/A"
    }
    try {
        switch ($Event.Id) {
            302 {
                if ($Event.Properties.Count -gt 0) { $eventData.Username = $Event.Properties[0].Value }
                if ($Event.Properties.Count -gt 1) { $eventData.ExternalIP = $Event.Properties[1].Value }
                if ($Event.Properties.Count -gt 2) { $eventData.InternalIP = $Event.Properties[2].Value }
                if ($Event.Properties.Count -gt 3) { $eventData.Protocol = $Event.Properties[3].Value }
                $eventData.ErrorCode = "0"
            }
            303 {
                if ($Event.Properties.Count -gt 0) { $eventData.Username = $Event.Properties[0].Value }
                if ($Event.Properties.Count -gt 1) { $eventData.ExternalIP = $Event.Properties[1].Value }
                if ($Event.Properties.Count -gt 2) { $eventData.InternalIP = $Event.Properties[2].Value }
                if ($Event.Properties.Count -gt 3) { $eventData.Protocol = $Event.Properties[3].Value }
                if ($Event.Properties.Count -gt 4) { $eventData.ErrorCode = $Event.Properties[4].Value }
            }
        }
    } catch {
        Write-Log "RD Gateway event parse error: $($_.Exception.Message)"
    }
    return $eventData
}

function Format-RDGatewayEvent {
    param(
        [int]$EventID,
        [string]$Username,
        [string]$ExternalIP,
        [string]$InternalIP,
        [string]$Protocol,
        [string]$ErrorCode,
        [datetime]$TimeCreated
    )

    $hUser = (ConvertTo-TelegramHtml $Username)
    $hExt = (ConvertTo-TelegramHtml $ExternalIP)
    $hInt = (ConvertTo-TelegramHtml $InternalIP)
    $hProto = (ConvertTo-TelegramHtml $Protocol)
    $hTime = (ConvertTo-TelegramHtml ($TimeCreated.ToString('dd.MM.yyyy HH:mm:ss')))

    $message = "<b>"
    if ($EventID -eq 302) { $message += "RD Gateway connection OK" }
    elseif ($EventID -eq 303) { $message += "RD Gateway connection FAILED" }
    else { $message += "RD Gateway event" }
    $message += "</b>`r`n"

    $message += "User: $hUser`r`n"
    $message += "Client IP: $hExt`r`n"
    $message += "Target IP: $hInt`r`n"
    $message += "Protocol: $hProto`r`n"
    if ($EventID -eq 303 -and $ErrorCode -ne "0" -and $ErrorCode -ne "N/A") {
        $message += "Error: $(ConvertTo-TelegramHtml $ErrorCode)`r`n"
    }
    $message += "Time: $hTime`r`n"
    $message += "Event ID: $EventID"
    return $message
}

function Send-DailyReport {
    try {
        $quserOutput = @(& quser 2>$null)
        $usernames = [System.Collections.Generic.List[string]]::new()
        if ($quserOutput -and $quserOutput.Count -gt 1) {
            $sessionLines = @($quserOutput | Select-Object -Skip 1)
            foreach ($raw in $sessionLines) {
                $line = ($raw -replace '\s+', ' ').Trim()
                if ([string]::IsNullOrWhiteSpace($line)) { continue }
                $parts = $line -split ' ', 2
                if ($parts.Count -lt 1) { continue }
                $u = $parts[0].Trim()
                if (-not [string]::IsNullOrWhiteSpace($u) -and $u -ne 'USERNAME') {
                    $usernames.Add($u) | Out-Null
                }
            }
        }
        $count = $usernames.Count
        # PS 5.1: a single name can be a scalar (no .Count); empty list is $null
        $uniqueUsers = @($usernames | Sort-Object -Unique)
        $message = "<b>Daily report (quser)</b>`r`n"
        $message += "Server: $(ConvertTo-TelegramHtml $env:COMPUTERNAME)`r`n"
        $message += "Time: $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')`r`n"
        $message += "Active sessions: $count`r`n"
        if ($uniqueUsers.Count -gt 0) {
            $message += "`r`n<b>Unique logon names ($($uniqueUsers.Count)):</b>`r`n"
            foreach ($name in $uniqueUsers) {
                $safe = [System.Net.WebUtility]::HtmlEncode($name)
                $message += "  - $safe`r`n"
            }
        } else {
            $message += "`r`n<i>User list not available (quser empty or insufficient rights).</i>"
        }
        Send-TelegramMessage -Message $message | Out-Null
        Write-TextFileUtf8Bom -Path $LastReportFile -Text ((Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))
        Write-Log "Daily report sent to Telegram"
        return $true
    } catch {
        Write-Log "Daily report error: $($_.Exception.Message)"
        return $false
    }
}

function Check-AndSendDailyReport {
    $lastReport = $null
    if (Test-Path $LastReportFile) {
        $txt = Get-Content $LastReportFile -ErrorAction SilentlyContinue
        if ($txt) { $lastReport = [datetime]::ParseExact($txt, "yyyy-MM-dd HH:mm:ss", $null) }
    }

    $now = Get-Date
    $reportSlotToday = Get-Date -Year $now.Year -Month $now.Month -Day $now.Day -Hour $DailyReportHour -Minute $DailyReportMinute -Second 0
    $shouldSend = $false
    if ($now -ge $reportSlotToday) {
        if ($null -eq $lastReport) {
            $shouldSend = $true
        } else {
            $dLast = $lastReport.Date
            if ($dLast -lt $now.Date) { $shouldSend = $true }
        }
    }
    if ($shouldSend) { Send-DailyReport | Out-Null }

    return (Get-NextLocalSlotBoundary -Hour $DailyReportHour -Minute $DailyReportMinute)
}

function Start-LoginMonitor {
    param(
        [int]$MonitorInterval = 5,
        [switch]$MonitorAllEvents = $false,
        [switch]$MonitorInteractiveOnly = $true
    )

    Write-Log "========================================"
    Write-Log "Starting login event monitor"
    Write-Log "Monitoring logon types: 2,3,10 (when not in monitor-all mode)"
    Write-Log "========================================"

    Cleanup-OldLogs
    Send-Heartbeat -IsStartup
    Enable-SecurityAudit

    $rdGatewayAvailable = $false
    if ($EnableRDGatewayMonitoring) { $rdGatewayAvailable = Test-RDGatewayLog }

    $nextHeartbeatTime = (Get-Date).AddSeconds($HeartbeatInterval)
    $nextRotationCheck = Check-AndRotateLog
    $nextReportCheck = Check-AndSendDailyReport
    $lastCheckTime = (Get-Date).AddSeconds(-10)
    $lastGatewayCheckTime = (Get-Date).AddSeconds(-10)
    $monitorEvents = @(4624, 4625, 4648)

    while ($true) {
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName = 'Security'
                ID = $monitorEvents
                StartTime = $lastCheckTime
            } -ErrorAction SilentlyContinue

            if ($events) {
                foreach ($event in $events) {
                    if ($event.TimeCreated -le $lastCheckTime) { continue }

                    $eventInfo = Get-LoginEventInfo -Event $event
                    $logonTypeName = Get-LogonTypeName -LogonType $eventInfo.LogonType
                    $shouldIgnore = $false

                    if ($MonitorInteractiveOnly -and -not $MonitorAllEvents) {
                        if ($event.Id -eq 4648) {
                            $shouldIgnore = $true
                        } elseif ($event.Id -in 4624, 4625) {
                            $interactiveTypes = @(2, 3, 10)
                            if ($interactiveTypes -notcontains $eventInfo.LogonType) {
                                $shouldIgnore = $true
                            }
                        } else {
                            $shouldIgnore = $true
                        }
                    }

                    if (-not $shouldIgnore -and -not $MonitorAllEvents) {
                        $shouldIgnore = Should-IgnoreEvent -Username $eventInfo.Username `
                            -ProcessName $eventInfo.ProcessName `
                            -ComputerName $eventInfo.ComputerName `
                            -EventID $event.Id `
                            -LogonType $eventInfo.LogonType `
                            -SourceIP $eventInfo.SourceIP
                    }

                    if (-not $shouldIgnore) {
                        $formattedMessage = Format-LoginEvent -EventID $event.Id `
                            -Username $eventInfo.Username `
                            -ComputerName $eventInfo.ComputerName `
                            -SourceIP $eventInfo.SourceIP `
                            -ProcessName $eventInfo.ProcessName `
                            -TimeCreated $eventInfo.TimeCreated `
                            -LogonType $eventInfo.LogonType `
                            -LogonTypeName $logonTypeName `
                            -SecurityLogComputerName $event.MachineName

                        Write-Log "Notify: ID=$($event.Id) User=$($eventInfo.Username) LT=$($eventInfo.LogonType) IP=$($eventInfo.SourceIP)"
                        Send-TelegramMessage -Message $formattedMessage | Out-Null
                    }
                }
                $lastCheckTime = ($events | Measure-Object -Property TimeCreated -Maximum | Select-Object -ExpandProperty Maximum).AddSeconds(1)
            }

            if ($rdGatewayAvailable) {
                $gatewayEvents = Get-WinEvent -FilterHashtable @{
                    LogName = $RDGatewayLogName
                    ID = $RDGatewayEvents
                    StartTime = $lastGatewayCheckTime
                } -ErrorAction SilentlyContinue

                if ($gatewayEvents) {
                    foreach ($event in $gatewayEvents) {
                        if ($event.TimeCreated -le $lastGatewayCheckTime) { continue }
                        $ei = Get-RDGatewayEventInfo -Event $event
                        if ($ei.Username -like "*$") { continue }
                        $msg = Format-RDGatewayEvent -EventID $event.Id `
                            -Username $ei.Username `
                            -ExternalIP $ei.ExternalIP `
                            -InternalIP $ei.InternalIP `
                            -Protocol $ei.Protocol `
                            -ErrorCode $ei.ErrorCode `
                            -TimeCreated $ei.TimeCreated
                        Write-Log "Notify RDG: ID=$($event.Id) User=$($ei.Username)"
                        Send-TelegramMessage -Message $msg | Out-Null
                    }
                    $lastGatewayCheckTime = ($gatewayEvents | Measure-Object -Property TimeCreated -Maximum | Select-Object -ExpandProperty Maximum).AddSeconds(1)
                }
            }

            $now = Get-Date
            if ($now -ge $nextHeartbeatTime) {
                Send-Heartbeat
                $nextHeartbeatTime = $nextHeartbeatTime.AddSeconds($HeartbeatInterval)
            }
            if ($now -ge $nextRotationCheck) {
                $nextRotationCheck = Check-AndRotateLog
            }
            if ($now -ge $nextReportCheck) {
                $nextReportCheck = Check-AndSendDailyReport
            }
        } catch {
            Write-Log "Monitor loop error: $($_.Exception.Message)"
        }
        Start-Sleep -Seconds $MonitorInterval
    }
}

$script:StopNotificationSent = $false
try {
    Test-TelegramConnection | Out-Null
    Start-LoginMonitor -MonitorInterval 5 -MonitorInteractiveOnly
} catch {
    Write-Log "Fatal error: $($_.Exception.Message)"
    Send-StopNotification -Reason "Fatal error: $($_.Exception.Message)"
    $script:StopNotificationSent = $true
    throw
} finally {
    if (-not $script:StopNotificationSent) {
        Send-StopNotification -Reason "Script exited"
    }
}

