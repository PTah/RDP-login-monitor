<#
.SYNOPSIS
    Мониторинг Exchange: очереди транспорта, пересылка на внешние адреса (Inbox rules + mailbox forwarding + transport rules).
.DESCRIPTION
    Запуск на сервере с Exchange Management Shell (локальный snap-in или remote).
    Режимы: -Mode Queues (каждые 10 мин по задаче), -Mode Inbox (ежедневный скан), -Watchdog (проверка heartbeat).
    Установка задач: -InstallTasks
.NOTES
    Каталог: C:\ProgramData\RDP-login-monitor\
    Опционально: exchange_monitor.settings.ps1 в том же каталоге (секреты, whitelist).
#>

[CmdletBinding()]
param(
    [ValidateSet('Queues', 'Inbox', 'Watchdog')]
    [string]$Mode = 'Queues',
    [switch]$InstallTasks,
    [switch]$Watchdog
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================
# КОНФИГУРАЦИЯ
# ============================================

$ScriptVersion = '1.6.3'
$script:InstallRoot = [System.IO.Path]::GetFullPath("$env:ProgramData\RDP-login-monitor")
$script:CanonicalScriptName = 'Exchange-MailSecurity.ps1'
$LogFile = Join-Path $script:InstallRoot 'Logs\exchange_mail_security.log'
$WatchdogLogFile = Join-Path $script:InstallRoot 'Logs\exchange_watchdog.log'
$QueuesHeartbeatFile = Join-Path $script:InstallRoot 'Logs\last_exchange_queues_ok.txt'
$InboxHeartbeatFile = Join-Path $script:InstallRoot 'Logs\last_exchange_inbox_scan_ok.txt'
$ForwardingBaselineFile = Join-Path $script:InstallRoot 'Logs\exchange_forwarding_baseline.json'
$QueueAlertStateFile = Join-Path $script:InstallRoot 'Logs\exchange_queue_alert_state.json'

# --- Уведомления (как Login_Monitor.ps1; можно вынести в exchange_monitor.settings.ps1) ---
$NotifyOrder = 'tg'
$TelegramBotToken = ''
$TelegramChatID = ''
$TelegramBotTokenProtectedB64 = ''
$TelegramChatIDProtectedB64 = ''
$MailSmtpHost = ''
$MailSmtpPort = 587
$MailSmtpUser = ''
$MailSmtpPassword = ''
$MailSmtpPasswordProtectedB64 = ''
$MailFrom = ''
$MailTo = ''
$MailSmtpStartTls = $true
$MailSmtpSsl = $false

# --- Exchange / сканирование ---
$ExchangeServerFqdn = ''   # пусто = локальный snap-in на этом сервере
$QueueMessageCountThreshold = 150
$QueueAlertCooldownSeconds = 900
$ExternalDomainWhitelist = @()   # partner-bank.ru
$AlertOnlyOnNewForwardingFindings = $true
$ScanMailboxForwarding = $true
$ScanInboxRules = $true
$ScanTransportRules = $true
# VIP: только перечисленные ящики и/или шаблоны (пилот перед полным сканом).
$VipMailboxesOnly = $false
$VipMailboxes = @()              # точные PrimarySmtpAddress: user@domain.com
$VipMailboxPatterns = @()        # wildcard: *@kalinamall.ru, director*, finance*
$ExcludeMailboxPatterns = @('HealthMailbox*', 'DiscoveryMailbox*', 'SystemMailbox*')
$ScanDisabledInboxRulesWithExternalForward = $true   # отключённые правила с внешней пересылкой
$SuppressAlertsOnFirstBaselineRun = $true            # первый скан: baseline без всплеска алертов
$SendInboxScanSummary = $true                      # краткая сводка после скана
$InboxScanBatchSize = 50
$InboxScanBatchDelaySeconds = 3
$MaxMailboxesPerRun = 0   # 0 = без лимита
$QueuesHeartbeatStaleSeconds = 1200    # 20 мин
$InboxHeartbeatStaleSeconds = 93600   # 26 ч
$NotifyWhenForwardingScanClean = $false   # true = ежедневное «внешняя пересылка не найдена»

$script:ScheduledTaskQueues = 'RDP-Exchange-TransportQueues'
$script:ScheduledTaskInbox = 'RDP-Exchange-InboxRules'
$script:ScheduledTaskWatchdog = 'RDP-Exchange-MailSecurity-Watchdog'

# ============================================
# ИНИЦИАЛИЗАЦИЯ
# ============================================

if (!(Test-Path -LiteralPath $script:InstallRoot)) {
    New-Item -ItemType Directory -Path $script:InstallRoot -Force | Out-Null
}
$LogDir = Split-Path $LogFile -Parent
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

$script:Utf8BomEncoding = New-Object System.Text.UTF8Encoding $true

$SettingsFile = Join-Path $script:InstallRoot 'exchange_monitor.settings.ps1'
if (Test-Path -LiteralPath $SettingsFile) {
    . $SettingsFile
}

function Write-NotifyLog {
    param([string]$Message)
    Write-ExchLog $Message
}

function Write-ExchLog {
    param([string]$Message)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "$timestamp - $Message" + [Environment]::NewLine
    [System.IO.File]::AppendAllText($LogFile, $logMessage, $script:Utf8BomEncoding)
    Write-Host ($logMessage.TrimEnd("`r`n"))
}

function Write-WdLog {
    param([string]$Message)
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "$timestamp - $Message" + [Environment]::NewLine
    [System.IO.File]::AppendAllText($WatchdogLogFile, $line, $script:Utf8BomEncoding)
    Write-Host ($line.TrimEnd("`r`n"))
}

function Test-RunningElevated {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        if ($null -ne $id.User -and $id.User.Value -eq 'S-1-5-18') { return $true }
        $p = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Get-ExchangeMonitorScriptPath {
    $p = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($p)) { $p = $MyInvocation.MyCommand.Path }
    if ([string]::IsNullOrWhiteSpace($p)) { return (Join-Path $script:InstallRoot $script:CanonicalScriptName) }
    return [System.IO.Path]::GetFullPath($p)
}

function Get-ExchangeMonitorPowerShellExe {
    return "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
}

# --- InstallTasks / Watchdog до dot-source уведомлений ---

function Register-ExchangeMonitorScheduledTasks {
    $psExe = Get-ExchangeMonitorPowerShellExe
    $scriptPath = Get-ExchangeMonitorScriptPath
    $argQueues = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -Mode Queues"
    $argInbox = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -Mode Inbox"
    $argWd = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -Watchdog"

    $schtasksExe = Join-Path $env:SystemRoot 'System32\schtasks.exe'
    $delEa = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'

    foreach ($tn in @($script:ScheduledTaskQueues, $script:ScheduledTaskInbox, $script:ScheduledTaskWatchdog)) {
        & $schtasksExe /Delete /TN $tn /F 2>$null | Out-Null
    }
    $ErrorActionPreference = $delEa

    $trQueues = "`"$psExe`" $argQueues"
    $outQ = & $schtasksExe /Create /F /RU SYSTEM /RL HIGHEST /SC MINUTE /MO 10 /TN $script:ScheduledTaskQueues /TR $trQueues 2>&1
    foreach ($line in @($outQ)) { Write-ExchLog "schtasks queues: $line" }

    $trInbox = "`"$psExe`" $argInbox"
    $outI = & $schtasksExe /Create /F /RU SYSTEM /RL HIGHEST /SC DAILY /ST 02:00 /TN $script:ScheduledTaskInbox /TR $trInbox 2>&1
    foreach ($line in @($outI)) { Write-ExchLog "schtasks inbox: $line" }

    $trWd = "`"$psExe`" $argWd"
    $outW = & $schtasksExe /Create /F /RU SYSTEM /RL HIGHEST /SC MINUTE /MO 15 /TN $script:ScheduledTaskWatchdog /TR $trWd 2>&1
    foreach ($line in @($outW)) { Write-ExchLog "schtasks watchdog: $line" }

    $ErrorActionPreference = 'SilentlyContinue'
    & $schtasksExe /Run /TN $script:ScheduledTaskQueues 2>&1 | Out-Null
    & $schtasksExe /Run /TN $script:ScheduledTaskWatchdog 2>&1 | Out-Null
    $ErrorActionPreference = 'Stop'

    Write-ExchLog "InstallTasks: registered $($script:ScheduledTaskQueues), $($script:ScheduledTaskInbox), $($script:ScheduledTaskWatchdog)"
}

if ($Watchdog) { $Mode = 'Watchdog' }

# Уведомления
$notifyPath = Join-Path $script:InstallRoot 'Notify-Common.ps1'
if (-not (Test-Path -LiteralPath $notifyPath)) {
    $notifyPath = Join-Path (Split-Path -Parent (Get-ExchangeMonitorScriptPath)) 'Notify-Common.ps1'
}
if (-not (Test-Path -LiteralPath $notifyPath)) {
    Write-Host "Notify-Common.ps1 not found near $script:InstallRoot"
    exit 1
}
. $notifyPath

$tgToken = [ref]$TelegramBotToken
$tgChat = [ref]$TelegramChatID
$mailPass = [ref]$MailSmtpPassword
Initialize-NotifyCredentials -TelegramBotTokenProtectedB64 $TelegramBotTokenProtectedB64 `
    -TelegramChatIDProtectedB64 $TelegramChatIDProtectedB64 `
    -TelegramBotToken $tgToken -TelegramChatID $tgChat `
    -MailSmtpPasswordProtectedB64 $MailSmtpPasswordProtectedB64 -MailSmtpPassword $mailPass
if ($TelegramBotToken -eq '<TELEGRAM_BOT_TOKEN>') { $TelegramBotToken = '' }
if ($TelegramChatID -eq '<TELEGRAM_CHAT_ID>') { $TelegramChatID = '' }

function Send-ExchangeInstallNotification {
    $scope = Get-ExchangeInboxScanScopeLabel
    $vipNote = if ($VipMailboxesOnly) { "VIP on ($scope)" } else { 'VIP off (full scan)' }
    $firstScan = if ($SuppressAlertsOnFirstBaselineRun) { 'baseline, no alert flood on first run' } else { 'alert on all findings' }
    $msg = "<b>Exchange Mail Security installed</b>`r`n"
    $msg += "Host: $(ConvertTo-TelegramHtml $env:COMPUTERNAME) | v$ScriptVersion`r`n"
    $msg += "Notify: $(ConvertTo-TelegramHtml (Get-NotifyChainHuman))`r`n"
    $msg += "Inbox/forward: $vipNote`r`n"
    $msg += "Queues threshold: $QueueMessageCountThreshold | Inbox 02:00 | Queues every 10 min`r`n"
    $msg += "First scan: $firstScan"
    Send-MonitorNotification -Message $msg -EmailSubject 'Exchange Mail Security: install' | Out-Null
}

if ($InstallTasks) {
    if (-not (Test-RunningElevated)) {
        Write-Host 'InstallTasks: run as Administrator.'
        exit 1
    }
    Register-ExchangeMonitorScheduledTasks
    if ((Test-NotifyTelegramConfigured) -or (Test-NotifyEmailConfigured)) {
        Send-ExchangeInstallNotification
        Write-ExchLog 'InstallTasks: install notification sent'
    }
    exit 0
}

# ============================================
# EXCHANGE EMS
# ============================================

$script:ExchangeSessionLoaded = $false

function Import-ExchangeManagementShell {
    if ($script:ExchangeSessionLoaded) { return $true }

    $snapins = @(Get-PSSnapin -Registered -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match 'Microsoft\.Exchange\.Management\.PowerShell'
    })
    if ($snapins.Count -gt 0) {
        Add-PSSnapin -Name $snapins[0].Name -ErrorAction Stop
        $script:ExchangeSessionLoaded = $true
        Write-ExchLog "Exchange: snap-in $($snapins[0].Name)"
        return $true
    }

    $rex = Join-Path ${env:ExchangeInstallPath} 'bin\RemoteExchange.ps1'
    if ([string]::IsNullOrWhiteSpace(${env:ExchangeInstallPath})) {
        $candidates = @(
            'C:\Program Files\Microsoft\Exchange Server\V15\bin\RemoteExchange.ps1',
            'C:\Program Files\Microsoft\Exchange Server\V14\bin\RemoteExchange.ps1'
        )
        foreach ($c in $candidates) {
            if (Test-Path -LiteralPath $c) { $rex = $c; break }
        }
    }
    if (Test-Path -LiteralPath $rex) {
        . $rex
        Import-ExchangeCmdlet -DisableNameVerifying -ErrorAction Stop
        $script:ExchangeSessionLoaded = $true
        Write-ExchLog "Exchange: RemoteExchange $rex"
        return $true
    }

    if (-not [string]::IsNullOrWhiteSpace($ExchangeServerFqdn)) {
        $uri = "http://$ExchangeServerFqdn/PowerShell/"
        $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $uri -Authentication Kerberos -ErrorAction Stop
        Import-PSSession $session -DisableNameChecking -AllowClobber -ErrorAction Stop | Out-Null
        $script:ExchangeSessionLoaded = $true
        Write-ExchLog "Exchange: PSSession $uri"
        return $true
    }

    throw 'Failed to load Exchange Management Shell (snap-in / RemoteExchange / set $ExchangeServerFqdn).'
}

# ============================================
# ВНЕШНИЕ ДОМЕНЫ
# ============================================

function Get-InternalAcceptedDomainNames {
    Import-ExchangeManagementShell
    $names = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $domains = Get-AcceptedDomain -ErrorAction Stop
    foreach ($d in $domains) {
        if ($d.DomainType -eq 'Authoritative' -or $d.DomainType -eq 'InternalRelay') {
            $null = $names.Add([string]$d.DomainName)
        }
    }
    return $names
}

function Get-EmailDomainFromAddress {
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return $null }
    $a = $Address.Trim().ToLowerInvariant()
    if ($a -match 'smtp:([^@\s]+@([^@\s;]+))') { return $matches[2] }
    if ($a -match '([a-z0-9._%+-]+@([a-z0-9.-]+\.[a-z]{2,}))') { return $matches[2] }
    return $null
}

function Get-AddressesFromExchangeProperty {
    param($PropertyValue)
    $list = [System.Collections.Generic.List[string]]::new()
    if ($null -eq $PropertyValue) { return @() }
    foreach ($item in @($PropertyValue)) {
        $s = [string]$item
        if ([string]::IsNullOrWhiteSpace($s)) { continue }
        if ($s -match 'smtp:([^;\s]+@[^;\s]+)') {
            $list.Add($matches[1].ToLowerInvariant()) | Out-Null
        } elseif ($s -match '([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})') {
            $list.Add($matches[1].ToLowerInvariant()) | Out-Null
        }
    }
    return @($list)
}

function Test-IsExternalSmtpAddress {
    param(
        [string]$SmtpAddress,
        [System.Collections.Generic.HashSet[string]]$InternalDomains,
        [string[]]$WhitelistDomains
    )

    $domain = Get-EmailDomainFromAddress -Address $SmtpAddress
    if ([string]::IsNullOrWhiteSpace($domain)) { return $false }

    foreach ($w in $WhitelistDomains) {
        if ([string]::IsNullOrWhiteSpace($w)) { continue }
        if ($domain -eq $w.Trim().ToLowerInvariant()) { return $false }
    }

    return -not $InternalDomains.Contains($domain)
}

function Test-MailboxExcluded {
    param([string]$PrimarySmtp)
    foreach ($pat in $ExcludeMailboxPatterns) {
        if ([string]::IsNullOrWhiteSpace($pat)) { continue }
        if ($PrimarySmtp -like $pat) { return $true }
    }
    return $false
}

function Test-VipMailboxScopeConfigured {
    if (-not $VipMailboxesOnly) { return $true }
    $hasList = @($VipMailboxes | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -gt 0
    $hasPat = @($VipMailboxPatterns | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -gt 0
    return ($hasList -or $hasPat)
}

function Test-MailboxInVipScope {
    param([string]$PrimarySmtp)

    if (-not $VipMailboxesOnly) { return $true }
    if (-not (Test-VipMailboxScopeConfigured)) { return $false }

    $smtp = $PrimarySmtp.Trim().ToLowerInvariant()
    foreach ($v in $VipMailboxes) {
        if ([string]::IsNullOrWhiteSpace($v)) { continue }
        if ($smtp -eq $v.Trim().ToLowerInvariant()) { return $true }
    }
    foreach ($pat in $VipMailboxPatterns) {
        if ([string]::IsNullOrWhiteSpace($pat)) { continue }
        if ($smtp -like $pat) { return $true }
    }
    return $false
}

function Get-ExchangeInboxScanScopeLabel {
    if (-not $VipMailboxesOnly) {
        if ($MaxMailboxesPerRun -gt 0) { return "all mailboxes (limit $MaxMailboxesPerRun)" }
        return 'all mailboxes'
    }
    $n = @($VipMailboxes | Where-Object { $_ }).Count
    $p = @($VipMailboxPatterns | Where-Object { $_ }).Count
    return "VIP list=$n patterns=$p"
}

# ============================================
# FINDINGS
# ============================================

function New-ForwardingFinding {
    param(
        [string]$FindingType,
        [string]$Mailbox,
        [string]$RuleName,
        [string]$TargetAddress,
        [string]$Severity,
        [hashtable]$Extra = @{}
    )

    $rulePart = if ([string]::IsNullOrWhiteSpace($RuleName)) { '' } else { $RuleName }
    $enabledPart = 'na'
    if ($Extra.ContainsKey('Enabled')) {
        $enabledPart = if ($Extra['Enabled']) { 'on' } else { 'off' }
    }
    $id = '{0}|{1}|{2}|{3}|{4}' -f $FindingType, $Mailbox.ToLowerInvariant(), $rulePart, $TargetAddress.ToLowerInvariant(), $enabledPart
    return [pscustomobject]@{
        Id = $id
        FindingType = $FindingType
        Mailbox = $Mailbox
        RuleName = $RuleName
        TargetAddress = $TargetAddress
        Severity = $Severity
        Extra = $Extra
    }
}

function Format-ForwardingFindingMessage {
    param($Finding)

    $hType = ConvertTo-TelegramHtml $Finding.FindingType
    $hMb = ConvertTo-TelegramHtml $Finding.Mailbox
    $hRule = ConvertTo-TelegramHtml $Finding.RuleName
    $hTarget = ConvertTo-TelegramHtml $Finding.TargetAddress
    $hSev = ConvertTo-TelegramHtml $Finding.Severity
    $hostName = ConvertTo-TelegramHtml $env:COMPUTERNAME

    $msg = "<b>Exchange: external forward</b>`r`n"
    $msg += "Host: $hostName`r`n"
    $msg += "Type: $hType`r`n"
    $msg += "Mailbox: $hMb`r`n"
    if (-not [string]::IsNullOrWhiteSpace($Finding.RuleName)) {
        $msg += "Rule: $hRule`r`n"
    }
    $msg += "Target: $hTarget (external)`r`n"
    $msg += "Severity: $hSev`r`n"

    if ($Finding.Extra.ContainsKey('Enabled')) {
        $msg += "Enabled: $(ConvertTo-TelegramHtml ([string]$Finding.Extra['Enabled']))`r`n"
    }
    if ($Finding.Extra.ContainsKey('DeleteMessage')) {
        $msg += "DeleteMessage: $(ConvertTo-TelegramHtml ([string]$Finding.Extra['DeleteMessage']))`r`n"
    }
    if ($Finding.Extra.ContainsKey('MarkAsRead')) {
        $msg += "MarkAsRead: $(ConvertTo-TelegramHtml ([string]$Finding.Extra['MarkAsRead']))`r`n"
    }
    if ($Finding.Extra.ContainsKey('DeliverToMailboxAndForward')) {
        $msg += "DeliverToMailboxAndForward: $(ConvertTo-TelegramHtml ([string]$Finding.Extra['DeliverToMailboxAndForward']))`r`n"
    }
    if ($Finding.Extra.ContainsKey('Property')) {
        $msg += "Rule property: $(ConvertTo-TelegramHtml ([string]$Finding.Extra['Property']))`r`n"
    }

    return $msg
}

function Get-ForwardingBaseline {
    if (-not (Test-Path -LiteralPath $ForwardingBaselineFile)) {
        return @{ FindingIds = @(); LastScanUtc = $null }
    }
    try {
        $raw = Get-Content -LiteralPath $ForwardingBaselineFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $ids = @()
        if ($null -ne $raw.FindingIds) { $ids = @($raw.FindingIds) }
        return @{ FindingIds = $ids; LastScanUtc = $raw.LastScanUtc }
    } catch {
        Write-ExchLog "Baseline: read failed ($($_.Exception.Message))"
        return @{ FindingIds = @(); LastScanUtc = $null }
    }
}

function Save-ForwardingBaseline {
    param([string[]]$FindingIds)
    $obj = @{
        LastScanUtc = (Get-Date).ToUniversalTime().ToString('o')
        FindingIds = @($FindingIds)
    }
    $json = $obj | ConvertTo-Json -Depth 4
    Write-TextFileUtf8Bom -Path $ForwardingBaselineFile -Text $json
}

function Write-TextFileUtf8Bom {
    param([string]$Path, [string]$Text)
    [System.IO.File]::WriteAllText($Path, $Text, $script:Utf8BomEncoding)
}

# ============================================
# SCAN: QUEUES
# ============================================

function Get-QueueAlertState {
    if (-not (Test-Path -LiteralPath $QueueAlertStateFile)) { return @{} }
    try {
        $h = @{}
        (Get-Content -LiteralPath $QueueAlertStateFile -Raw -Encoding UTF8 | ConvertFrom-Json).PSObject.Properties | ForEach-Object {
            $h[$_.Name] = [datetime]$_.Value
        }
        return $h
    } catch { return @{} }
}

function Save-QueueAlertState {
    param([hashtable]$State)
    $obj = @{}
    foreach ($k in $State.Keys) { $obj[$k] = $State[$k].ToUniversalTime().ToString('o') }
    Write-TextFileUtf8Bom -Path $QueueAlertStateFile -Text ($obj | ConvertTo-Json)
}

function Invoke-ExchangeQueueScan {
    Import-ExchangeManagementShell
    Write-ExchLog "Queues: threshold MessageCount > $QueueMessageCountThreshold"

    $queues = @(Get-Queue -ErrorAction Stop)
    $hot = @($queues | Where-Object { $_.MessageCount -gt $QueueMessageCountThreshold })
    $state = Get-QueueAlertState
    $now = Get-Date

    if ($hot.Count -eq 0) {
        Write-ExchLog "Queues: OK (total $($queues.Count), above threshold 0)"
        Write-TextFileUtf8Bom -Path $QueuesHeartbeatFile -Text (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        return
    }

    foreach ($q in $hot) {
        $qKey = [string]$q.Identity
        $lastAlert = $null
        if ($state.ContainsKey($qKey)) { $lastAlert = $state[$qKey] }
        $cooldownOk = ($null -eq $lastAlert) -or (((Get-Date).ToUniversalTime() - $lastAlert.ToUniversalTime()).TotalSeconds -ge $QueueAlertCooldownSeconds)
        if (-not $cooldownOk) {
            Write-ExchLog "Queues: $($q.Identity) count=$($q.MessageCount) - cooldown, skip alert"
            continue
        }

        $hId = ConvertTo-TelegramHtml $q.Identity
        $msg = "<b>Exchange: transport queue</b>`r`n"
        $msg += "Host: $(ConvertTo-TelegramHtml $env:COMPUTERNAME)`r`n"
        $msg += "Queue: $hId`r`n"
        $msg += "Messages: <b>$($q.MessageCount)</b> (threshold $QueueMessageCountThreshold)`r`n"
        $msg += "Status: $(ConvertTo-TelegramHtml ([string]$q.Status))`r`n"
        $msg += "Time: $(ConvertTo-TelegramHtml (Get-Date -Format 'dd.MM.yyyy HH:mm:ss'))"

        if (Send-MonitorNotification -Message $msg -EmailSubject 'Exchange: transport queue') {
            $state[$qKey] = $now
            Write-ExchLog "Queues: alert sent for $($q.Identity)"
        }
    }

    Save-QueueAlertState -State $state
    Write-TextFileUtf8Bom -Path $QueuesHeartbeatFile -Text (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
}

# ============================================
# SCAN: FORWARDING
# ============================================

function Get-MailboxListForScan {
    Import-ExchangeManagementShell

    if ($VipMailboxesOnly) {
        if (-not (Test-VipMailboxScopeConfigured)) {
            throw 'VipMailboxesOnly=$true but VipMailboxes and VipMailboxPatterns are empty - set them in exchange_monitor.settings.ps1'
        }
        $set = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($v in $VipMailboxes) {
            if (-not [string]::IsNullOrWhiteSpace($v)) { $null = $set.Add($v.Trim().ToLowerInvariant()) }
        }
        if ($VipMailboxPatterns.Count -gt 0) {
            $all = @(Get-Mailbox -ResultSize Unlimited -ErrorAction Stop)
            foreach ($mb in $all) {
                $smtp = [string]$mb.PrimarySmtpAddress
                if ([string]::IsNullOrWhiteSpace($smtp)) { continue }
                if (Test-MailboxExcluded -PrimarySmtp $smtp) { continue }
                if (Test-MailboxInVipScope -PrimarySmtp $smtp) {
                    $null = $set.Add($smtp.ToLowerInvariant())
                }
            }
        }
        return @($set)
    }

    $all = @(Get-Mailbox -ResultSize Unlimited -ErrorAction Stop)
    $list = [System.Collections.Generic.List[string]]::new()
    foreach ($mb in $all) {
        $smtp = [string]$mb.PrimarySmtpAddress
        if ([string]::IsNullOrWhiteSpace($smtp)) { continue }
        if (Test-MailboxExcluded -PrimarySmtp $smtp) { continue }
        $list.Add($smtp.ToLowerInvariant()) | Out-Null
        if ($MaxMailboxesPerRun -gt 0 -and $list.Count -ge $MaxMailboxesPerRun) { break }
    }
    return @($list)
}

function Scan-MailboxForwardingSettings {
    param(
        [System.Collections.Generic.HashSet[string]]$InternalDomains,
        [System.Collections.Generic.List[object]]$Findings
    )

    if (-not $ScanMailboxForwarding) { return }

    Write-ExchLog 'Forwarding: Get-Mailbox (ForwardingSmtpAddress / ForwardingAddress)'
    $mbs = Get-Mailbox -ResultSize Unlimited -ErrorAction Stop | Where-Object {
        $_.ForwardingSmtpAddress -or $_.ForwardingAddress
    }

    foreach ($mb in $mbs) {
        $primary = [string]$mb.PrimarySmtpAddress
        if (Test-MailboxExcluded -PrimarySmtp $primary) { continue }
        if (-not (Test-MailboxInVipScope -PrimarySmtp $primary)) { continue }

        $targets = @()
        if ($mb.ForwardingSmtpAddress) {
            $targets += @($mb.ForwardingSmtpAddress)
        }
        if ($mb.ForwardingAddress) {
            $targets += @((Get-AddressesFromExchangeProperty -PropertyValue $mb.ForwardingAddress))
        }

        foreach ($t in $targets) {
            if (-not (Test-IsExternalSmtpAddress -SmtpAddress $t -InternalDomains $InternalDomains -WhitelistDomains $ExternalDomainWhitelist)) {
                continue
            }
            $sev = 'High'
            $Findings.Add((New-ForwardingFinding -FindingType 'MailboxForwarding' -Mailbox $primary `
                -RuleName '' -TargetAddress $t -Severity $sev -Extra @{
                    DeliverToMailboxAndForward = [string]$mb.DeliverToMailboxAndForward
                })) | Out-Null
        }
    }
}

function Add-InboxRuleExternalForwardFindings {
    param(
        $Rule,
        [string]$Mailbox,
        [System.Collections.Generic.HashSet[string]]$InternalDomains,
        [System.Collections.Generic.List[object]]$Findings
    )

    $props = @(
        @{ Name = 'ForwardTo'; Value = $Rule.ForwardTo }
        @{ Name = 'RedirectTo'; Value = $Rule.RedirectTo }
        @{ Name = 'ForwardAsAttachmentTo'; Value = $Rule.ForwardAsAttachmentTo }
    )

    foreach ($p in $props) {
        $addrs = Get-AddressesFromExchangeProperty -PropertyValue $p.Value
        foreach ($addr in $addrs) {
            if (-not (Test-IsExternalSmtpAddress -SmtpAddress $addr -InternalDomains $InternalDomains -WhitelistDomains $ExternalDomainWhitelist)) {
                continue
            }
            $sev = 'High'
            if (-not $Rule.Enabled) {
                $sev = 'Medium (rule disabled)'
            } elseif ($Rule.DeleteMessage -or $Rule.MarkAsRead) {
                $sev = 'Critical'
            }
            $Findings.Add((New-ForwardingFinding -FindingType 'InboxRule' -Mailbox $Mailbox `
                -RuleName [string]$Rule.Name -TargetAddress $addr -Severity $sev -Extra @{
                    Enabled = [bool]$Rule.Enabled
                    DeleteMessage = $Rule.DeleteMessage
                    MarkAsRead = $Rule.MarkAsRead
                    Property = $p.Name
                })) | Out-Null
        }
    }
}

function Scan-InboxRulesForMailbox {
    param(
        [string]$Mailbox,
        [System.Collections.Generic.HashSet[string]]$InternalDomains,
        [System.Collections.Generic.List[object]]$Findings
    )

    $rules = @(Get-InboxRule -Mailbox $Mailbox -ErrorAction SilentlyContinue)
    foreach ($rule in $rules) {
        if ($rule.Enabled) {
            Add-InboxRuleExternalForwardFindings -Rule $rule -Mailbox $Mailbox -InternalDomains $InternalDomains -Findings $Findings
        } elseif ($ScanDisabledInboxRulesWithExternalForward) {
            Add-InboxRuleExternalForwardFindings -Rule $rule -Mailbox $Mailbox -InternalDomains $InternalDomains -Findings $Findings
        }
    }
}

function Scan-TransportRulesExternalForward {
    param(
        [System.Collections.Generic.HashSet[string]]$InternalDomains,
        [System.Collections.Generic.List[object]]$Findings
    )

    if (-not $ScanTransportRules) { return }

    Write-ExchLog 'Forwarding: Get-TransportRule'
    $rules = @(Get-TransportRule -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Enabled' })
    foreach ($rule in $rules) {
        $props = @(
            $rule.RedirectMessageTo
            $rule.BlindCopyTo
            $rule.CopyTo
        )
        foreach ($pv in $props) {
            $addrs = Get-AddressesFromExchangeProperty -PropertyValue $pv
            foreach ($addr in $addrs) {
                if (-not (Test-IsExternalSmtpAddress -SmtpAddress $addr -InternalDomains $InternalDomains -WhitelistDomains $ExternalDomainWhitelist)) {
                    continue
                }
                $Findings.Add((New-ForwardingFinding -FindingType 'TransportRule' -Mailbox '(transport)' `
                    -RuleName [string]$rule.Name -TargetAddress $addr -Severity 'High' -Extra @{})) | Out-Null
            }
        }
    }
}

function Send-ExchangeInboxScanSummary {
    param(
        [int]$TotalFindings,
        [int]$NewFindings,
        [int]$MailboxCount,
        [bool]$FirstBaselineSeeded,
        [string]$ScopeLabel
    )

    if (-not $SendInboxScanSummary) { return }

    $hHost = ConvertTo-TelegramHtml $env:COMPUTERNAME
    $msg = "<b>Exchange: forwarding scan summary</b>`r`n"
    $msg += "Host: $hHost | v$ScriptVersion`r`n"
    $msg += "Scope: $(ConvertTo-TelegramHtml $ScopeLabel)`r`n"
    $msg += "Mailboxes (Inbox rules): $MailboxCount`r`n"
    $msg += "Findings total: $TotalFindings | new: $NewFindings`r`n"
    if ($FirstBaselineSeeded) {
        $msg += "<i>First baseline: existing forwards suppressed (SuppressAlertsOnFirstBaselineRun).</i>`r`n"
    }
    Send-MonitorNotification -Message $msg -EmailSubject 'Exchange: scan summary' | Out-Null
}

function Invoke-ExchangeInboxAndForwardingScan {
    $scopeLabel = Get-ExchangeInboxScanScopeLabel
    Write-ExchLog "Inbox/Forwarding scan v$ScriptVersion; scope: $scopeLabel; notify: $(Get-NotifyChainHuman)"
    Import-ExchangeManagementShell
    $internalDomains = Get-InternalAcceptedDomainNames
    Write-ExchLog "Accepted domains (internal): $($internalDomains -join ', ')"

    $findings = [System.Collections.Generic.List[object]]::new()

    Scan-MailboxForwardingSettings -InternalDomains $internalDomains -Findings $findings

    $mailboxCount = 0
    if ($ScanInboxRules) {
        $mailboxes = @(Get-MailboxListForScan)
        $mailboxCount = $mailboxes.Count
        Write-ExchLog "Inbox rules: mailboxes to scan: $mailboxCount ($scopeLabel)"
        $idx = 0
        foreach ($mb in $mailboxes) {
            $idx++
            try {
                Scan-InboxRulesForMailbox -Mailbox $mb -InternalDomains $internalDomains -Findings $findings
            } catch {
                Write-ExchLog "Inbox rules: error $mb : $($_.Exception.Message)"
            }
            if ($idx % $InboxScanBatchSize -eq 0) {
                Write-ExchLog "Inbox rules: processed $idx / $($mailboxes.Count)"
                Start-Sleep -Seconds $InboxScanBatchDelaySeconds
            }
        }
    }

    Scan-TransportRulesExternalForward -InternalDomains $internalDomains -Findings $findings

    $allIds = @($findings | ForEach-Object { $_.Id })
    $baseline = Get-ForwardingBaseline
    $prevSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($id in $baseline.FindingIds) { $null = $prevSet.Add($id) }

    $newFindings = @($findings | Where-Object { -not $prevSet.Contains($_.Id) })
    Write-ExchLog "Forwarding: total $($findings.Count), new $($newFindings.Count)"

    $isFirstBaseline = ($baseline.FindingIds.Count -eq 0) -and ($findings.Count -gt 0)
    $firstBaselineSeeded = $false

    $toAlert = if ($AlertOnlyOnNewForwardingFindings) { $newFindings } else { @($findings) }
    if ($SuppressAlertsOnFirstBaselineRun -and $isFirstBaseline) {
        Write-ExchLog 'Forwarding: first baseline - alerts suppressed (SuppressAlertsOnFirstBaselineRun)'
        $firstBaselineSeeded = $true
        $toAlert = @()
    }
    foreach ($f in $toAlert) {
        $body = Format-ForwardingFindingMessage -Finding $f
        Send-MonitorNotification -Message $body -EmailSubject 'Exchange: external forward' | Out-Null
    }

    if ($findings.Count -eq 0 -and $NotifyWhenForwardingScanClean) {
        $summary = "<b>Exchange: forwarding scan</b>`r`nNo external forward (Inbox / mailbox / transport).`r`nHost: $(ConvertTo-TelegramHtml $env:COMPUTERNAME)"
        Send-MonitorNotification -Message $summary -EmailSubject 'Exchange: forward scan OK' | Out-Null
    } elseif ($newFindings.Count -eq 0 -and $AlertOnlyOnNewForwardingFindings) {
        Write-ExchLog 'Forwarding: no changes (known findings in baseline only)'
    }

    Save-ForwardingBaseline -FindingIds $allIds
    Write-TextFileUtf8Bom -Path $InboxHeartbeatFile -Text (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    Send-ExchangeInboxScanSummary -TotalFindings $findings.Count -NewFindings $newFindings.Count `
        -MailboxCount $mailboxCount -FirstBaselineSeeded $firstBaselineSeeded -ScopeLabel $scopeLabel
    Write-ExchLog 'Inbox/Forwarding scan finished'
}

# ============================================
# WATCHDOG
# ============================================

function Get-HeartbeatAgeSeconds {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return [double]::PositiveInfinity }
    try {
        $t = Get-Content -LiteralPath $Path -TotalCount 1 -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($t)) { return [double]::PositiveInfinity }
        $dt = [datetime]::ParseExact($t.Trim(), 'yyyy-MM-dd HH:mm:ss', $null)
        return ((Get-Date) - $dt).TotalSeconds
    } catch { return [double]::PositiveInfinity }
}

function Invoke-ExchangeWatchdog {
    Write-WdLog "Watchdog Exchange-MailSecurity v$ScriptVersion"
    $issues = [System.Collections.Generic.List[string]]::new()

    $qAge = Get-HeartbeatAgeSeconds -Path $QueuesHeartbeatFile
    if ($qAge -gt $QueuesHeartbeatStaleSeconds) {
        $issues.Add("Queues: no successful scan > $([int]$qAge) s (threshold $QueuesHeartbeatStaleSeconds s)") | Out-Null
    }

    $iAge = Get-HeartbeatAgeSeconds -Path $InboxHeartbeatFile
    if ($iAge -gt $InboxHeartbeatStaleSeconds) {
        $issues.Add("Inbox/Forwarding: no successful scan > $([int]$iAge) s (threshold $InboxHeartbeatStaleSeconds s)") | Out-Null
    }

    if ($issues.Count -eq 0) {
        Write-WdLog 'Watchdog: heartbeat OK'
        exit 0
    }

    $msg = "<b>Exchange Mail Security: watchdog</b>`r`n"
    $msg += "Host: $(ConvertTo-TelegramHtml $env:COMPUTERNAME)`r`n"
    foreach ($iss in $issues) {
        $msg += "- $(ConvertTo-TelegramHtml $iss)`r`n"
    }

    Send-MonitorNotification -Message $msg -EmailSubject 'Exchange monitor: watchdog' | Out-Null
    Write-WdLog "Watchdog: alert sent ($($issues.Count) issue(s))"
    exit 1
}

# ============================================
# MAIN
# ============================================

if (-not (Test-RunningElevated)) {
    Write-ExchLog 'WARNING: not running elevated - EMS/tasks may fail.'
}

Write-ExchLog "=== Exchange-MailSecurity v$ScriptVersion Mode=$Mode ==="

try {
    switch ($Mode) {
        'Queues' { Invoke-ExchangeQueueScan }
        'Inbox' { Invoke-ExchangeInboxAndForwardingScan }
        'Watchdog' { Invoke-ExchangeWatchdog }
        default { throw "Unknown Mode: $Mode" }
    }
} catch {
    Write-ExchLog "ERROR: $($_.Exception.Message)"
    if ($_.ScriptStackTrace) { Write-ExchLog $_.ScriptStackTrace }
    exit 1
}

exit 0
