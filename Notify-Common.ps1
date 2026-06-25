<#
.SYNOPSIS
    Общие функции уведомлений (Telegram / SMTP) для скриптов RDP-login-monitor.
.DESCRIPTION
    Dot-source после определения Write-NotifyLog в вызывающем скрипте.
    Ожидает переменные: $NotifyOrder, $TelegramBotToken, $TelegramChatID,
    $MailSmtpHost, $MailFrom, $MailTo и др. (см. Login_Monitor.ps1).
#>

if (-not (Get-Command Write-NotifyLog -ErrorAction SilentlyContinue)) {
    function Write-NotifyLog {
        param([string]$Message)
        Write-Host $Message
    }
}

function Unprotect-RdpMonitorDpapiB64 {
    param([Parameter(Mandatory = $true)][string]$Base64)
    Add-Type -AssemblyName System.Security
    $bytes = [Convert]::FromBase64String($Base64.Trim())
    $plain = [System.Security.Cryptography.ProtectedData]::Unprotect(
        $bytes,
        $null,
        [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )
    return [Text.Encoding]::UTF8.GetString($plain)
}

function Initialize-NotifyCredentials {
    param(
        [string]$TelegramBotTokenProtectedB64 = '',
        [string]$TelegramChatIDProtectedB64 = '',
        [ref]$TelegramBotToken,
        [ref]$TelegramChatID,
        [string]$MailSmtpPasswordProtectedB64 = '',
        [ref]$MailSmtpPassword
    )

    if (-not [string]::IsNullOrWhiteSpace($TelegramBotTokenProtectedB64)) {
        $TelegramBotToken.Value = Unprotect-RdpMonitorDpapiB64 -Base64 $TelegramBotTokenProtectedB64
    }
    if (-not [string]::IsNullOrWhiteSpace($TelegramChatIDProtectedB64)) {
        $TelegramChatID.Value = Unprotect-RdpMonitorDpapiB64 -Base64 $TelegramChatIDProtectedB64
    }
    if (-not [string]::IsNullOrWhiteSpace($MailSmtpPasswordProtectedB64)) {
        $MailSmtpPassword.Value = Unprotect-RdpMonitorDpapiB64 -Base64 $MailSmtpPasswordProtectedB64
    }
}

function Test-NotifyTelegramConfigured {
    return (-not [string]::IsNullOrWhiteSpace($TelegramBotToken)) -and
        (-not [string]::IsNullOrWhiteSpace($TelegramChatID))
}

function Test-NotifyEmailConfigured {
    return (-not [string]::IsNullOrWhiteSpace($MailSmtpHost)) -and
        (-not [string]::IsNullOrWhiteSpace($MailFrom)) -and
        (-not [string]::IsNullOrWhiteSpace($MailTo))
}

function Get-NotifyOrderChannels {
    $configured = [System.Collections.Generic.List[string]]::new()
    if (Test-NotifyTelegramConfigured) { $configured.Add('telegram') | Out-Null }
    if (Test-NotifyEmailConfigured) { $configured.Add('email') | Out-Null }

    if ([string]::IsNullOrWhiteSpace($NotifyOrder)) {
        return @($configured)
    }

    $requested = [System.Collections.Generic.List[string]]::new()
    foreach ($part in ($NotifyOrder -split '[,\s;]+')) {
        $p = $part.Trim().ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        $channel = switch -Regex ($p) {
            '^(tg|telegram)$' { 'telegram' }
            '^(mail|email|e-mail)$' { 'email' }
            default {
                Write-NotifyLog "NotifyOrder: unknown channel '$part'"
                $null
            }
        }
        if ($null -eq $channel) { continue }
        if ($configured.Contains($channel) -and -not $requested.Contains($channel)) {
            $requested.Add($channel) | Out-Null
        }
    }
    return @($requested)
}

function Get-NotifyChainHuman {
    $channels = @(Get-NotifyOrderChannels)
    if ($channels.Count -eq 0) { return 'none (Telegram and SMTP not configured)' }
    $labels = foreach ($ch in $channels) {
        switch ($ch) {
            'telegram' { 'Telegram' }
            'email' { 'Email (SMTP)' }
            default { $ch }
        }
    }
    return ($labels -join ' → ')
}

function ConvertTo-TelegramHtml {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function Send-TelegramMessage {
    param([string]$Message)

    if (-not (Test-NotifyTelegramConfigured)) {
        Write-NotifyLog 'Telegram: token or chat_id missing'
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
        Write-NotifyLog "Telegram send error: $($_.Exception.Message)"
        return $false
    }
}

function ConvertTo-EmailHtmlBody {
    param([string]$TelegramHtmlMessage)
    $inner = [string]$TelegramHtmlMessage
    if ([string]::IsNullOrEmpty($inner)) { $inner = '' }
    $inner = $inner -replace "`r`n", "<br>`r`n"
    return @"
<html>
<body style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;line-height:1.4;">
$inner
</body>
</html>
"@
}

function Send-EmailNotification {
    param(
        [string]$Message,
        [string]$Subject = "RDP Login Monitor"
    )

    if (-not (Test-NotifyEmailConfigured)) {
        Write-NotifyLog 'Email: SMTP not configured'
        return $false
    }

    try {
        $toList = @($MailTo -split '[,;]' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($toList.Count -eq 0) { return $false }

        $mailParams = @{
            To          = $toList
            From        = $MailFrom.Trim()
            Subject     = $Subject
            Body        = (ConvertTo-EmailHtmlBody -TelegramHtmlMessage $Message)
            BodyAsHtml  = $true
            SmtpServer  = $MailSmtpHost.Trim()
            Port        = [int]$MailSmtpPort
            Encoding    = [System.Text.Encoding]::UTF8
            ErrorAction = 'Stop'
        }
        if ($MailSmtpSsl -or $MailSmtpStartTls) { $mailParams['UseSsl'] = $true }
        if (-not [string]::IsNullOrWhiteSpace($MailSmtpUser)) {
            $securePass = if ([string]::IsNullOrWhiteSpace($MailSmtpPassword)) {
                New-Object System.Security.SecureString
            } else {
                ConvertTo-SecureString $MailSmtpPassword -AsPlainText -Force
            }
            $mailParams['Credential'] = New-Object System.Management.Automation.PSCredential($MailSmtpUser.Trim(), $securePass)
        }

        Send-MailMessage @mailParams
        return $true
    } catch {
        Write-NotifyLog "Email send error: $($_.Exception.Message)"
        return $false
    }
}

function Send-MonitorNotification {
    param(
        [string]$Message,
        [string]$EmailSubject = "RDP Login Monitor"
    )

    $channels = @(Get-NotifyOrderChannels)
    if ($channels.Count -eq 0) {
        Write-NotifyLog 'Notification skipped: no channels configured'
        return $false
    }

    $anyOk = $false
    foreach ($ch in $channels) {
        $ok = switch ($ch) {
            'telegram' { Send-TelegramMessage -Message $Message }
            'email' { Send-EmailNotification -Message $Message -Subject $EmailSubject }
            default { $false }
        }
        if ($ok) { $anyOk = $true }
    }
    return $anyOk
}
