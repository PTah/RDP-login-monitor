<#
.SYNOPSIS
    Мониторинг логинов/попыток входа с уведомлениями в Telegram
.DESCRIPTION
    Отслеживает события входа в систему (Security 4624/4625) и события RD Gateway (302/303),
    отправляет уведомления в Telegram, делает ротацию логов, heartbeat в файл и ежедневный отчет.
.NOTES
    Требуется: PowerShell 5.0+, запуск от администратора.
    Важное:
    - На некоторых серверах RDP-логин приходит как LogonType=3, поэтому интерактивные типы: 2/3/10.
    - Добавлены исключения шума: DWM-*, UMFD-*, HealthMailbox*, Font Driver Host*, NtLmSsp и др.
    - Heartbeat без дрейфа: используется nextHeartbeatTime (а не "прошло N секунд").
#>

[CmdletBinding()]
param(
    [string]$TelegramBotToken = "<TELEGRAM_BOT_TOKEN>",
    [string]$TelegramChatID = "<TELEGRAM_CHAT_ID>"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ============================================
# КОНФИГУРАЦИЯ
# ============================================

# Логи
$LogFile = "D:\Soft\Logs\login_monitor.log"
$LogBackupFolder = "D:\Soft\Logs\Backup"
$MaxBackupDays = 30

# Ротация логов (ежедневно)
$LogRotationHour = 0
$LogRotationMinute = 0

# Heartbeat (только файл)
$HeartbeatInterval = 3600
$HeartbeatFile = "D:\Soft\Logs\last_heartbeat.txt"

# Ежедневный отчет
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

# Узкое исключение "шумовых" сетевых логонов (LogonType=3) от конкретных источников.
# Пример: Proxmox Mail Gateway / LDAP sync, которые периодически создают 4624 с LogonProcessName=Advapi.
$IgnoreAdvapiNetworkLogonSourceIps = @(
    "192.168.160.57"
)
$IgnoreAdvapiNetworkLogonProcessContains = "Advapi"

# ============================================
# ИНИЦИАЛИЗАЦИЯ
# ============================================

$LogDir = Split-Path $LogFile -Parent
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
if (!(Test-Path $LogBackupFolder)) { New-Item -ItemType Directory -Path $LogBackupFolder -Force | Out-Null }

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $Message"
    Add-Content -Path $LogFile -Value $logMessage -Force -Encoding UTF8
    Write-Host $logMessage
}

try {
    [System.Net.ServicePointManager]::SecurityProtocol =
        [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
    Write-Log "TLS 1.2 включен"
} catch {
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        Write-Log "TLS 1.2 установлен"
    } catch {
        Write-Log "ВНИМАНИЕ: Не удалось включить TLS 1.2"
    }
}

function Send-TelegramMessage {
    param([string]$Message)

    if ([string]::IsNullOrWhiteSpace($TelegramBotToken) -or [string]::IsNullOrWhiteSpace($TelegramChatID)) {
        Write-Log "Telegram: не задан токен/chat_id"
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
        Write-Log "Ошибка отправки в Telegram: $($_.Exception.Message)"
        return $false
    }
}

function Test-TelegramConnection {
    Write-Log "Проверка подключения к Telegram API..."
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
        $testUrl = "https://api.telegram.org/bot$TelegramBotToken/getMe"
        $response = Invoke-RestMethod -Uri $testUrl -Method Get -TimeoutSec 10 -ErrorAction Stop
        if ($response.ok) {
            Write-Log "Подключение к Telegram успешно. Бот: @$($response.result.username)"
            return $true
        }
    } catch {
        Write-Log "Ошибка подключения к Telegram: $($_.Exception.Message)"
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
    Write-Log "ОШИБКА: Скрипт должен быть запущен от имени администратора!"
    exit 1
}
Write-Log "Скрипт запущен с правами администратора"

function Enable-SecurityAudit {
    Write-Log "Проверка настроек аудита..."

    # Важно: auditpol пишет часть сообщений в stderr. Если перенаправлять stderr в $null,
    # PowerShell может превратить это в завершающую ошибку (и скрипт упадёт из-за $ErrorActionPreference=Stop).
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
        return ($r.Text -match 'Вход/выход')
    }

    function Test-SuccessAndFailureText {
        param([string]$Line)
        if ([string]::IsNullOrWhiteSpace($Line)) { return $false }
        # RU: "Успех и сбой" (часто в выводе категории)
        if ($Line -match '(?i)успех\s+и\s+сбой') { return $true }
        # Иногда встречается без пробелов вокруг "и" из-за форматирования/переносов
        if ($Line -match '(?i)успех\s*и\s*сбой') { return $true }
        # EN fallback
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

            # Ищем по подстроке без жёсткой привязки к количеству пробелов
            if ($t -notlike ('*{0}*' -f $SubcategoryLabel)) { continue }
            return [pscustomobject]@{ Ok = $true; ExitCode = 0; Text = $r.Text; Line = $t }
        }

        return [pscustomobject]@{ Ok = $true; ExitCode = 0; Text = $r.Text; Line = $null }
    }

    function Ensure-RuLogonLogoffSubcategories {
        # Как вы описали: смотрим категорию "Вход/выход" и добиваем две ключевые подкатегории.
        $category = "Вход/выход"
        $targets = @(
            "Вход в систему",
            "Выход из системы"
        )

        foreach ($sub in $targets) {
            $cur = Get-CategorySettingLine -CategoryName $category -SubcategoryLabel $sub
            if (-not $cur.Ok) {
                Write-Log ("Не удалось прочитать auditpol /get /category для '{0}' (код {1}). Вывод:`n{2}" -f $category, $cur.ExitCode, $cur.Text)
                return $false
            }

            if ($null -eq $cur.Line) {
                $frag = $cur.Text
                if ($frag.Length -gt 4000) { $frag = $frag.Substring(0, 4000) + "`n... (truncated)" }
                Write-Log ("В выводе категории '{0}' не найдена строка подкатегории '{1}'. Вывод (фрагмент):`n{2}" -f $category, $sub, $frag)
                return $false
            }

            if (Test-SuccessAndFailureText -Line $cur.Line) {
                Write-Log ("Аудит уже 'Успех и сбой' для: {0} :: {1}" -f $sub, $cur.Line)
                continue
            }

            Write-Log ("Требуется включить Success+Failure для подкатегории: {0}. Текущая строка: {1}" -f $sub, $cur.Line)
            $setArgs = ('/set /subcategory:"{0}" /success:enable /failure:enable' -f $sub)
            $set = Invoke-AuditPol -Arguments $setArgs
            if ($set.ExitCode -ne 0) {
                Write-Log ("auditpol SET FAIL (код {0}): {1}`n{2}" -f $set.ExitCode, $setArgs, $set.Text)
                return $false
            }

            $after = Get-CategorySettingLine -CategoryName $category -SubcategoryLabel $sub
            if ($null -ne $after.Line -and (Test-SuccessAndFailureText -Line $after.Line)) {
                Write-Log ("OK: подкатегория '{0}' приведена к 'Успех и сбой'. Строка: {1}" -f $sub, $after.Line)
            } else {
                Write-Log ("ПОСЛЕ SET строка для '{0}' всё ещё не похожа на 'Успех и сбой': {1}" -f $sub, $after.Line)
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
                Write-Log ("Не удалось прочитать auditpol /get /category для '{0}' (код {1}). Вывод:`n{2}" -f $category, $cur.ExitCode, $cur.Text)
                return $false
            }
            if ($null -eq $cur.Line) {
                Write-Log ("В выводе категории '{0}' не найдена строка подкатегории '{1}'." -f $category, $sub)
                return $false
            }
            if (Test-SuccessAndFailureText -Line $cur.Line) { continue }

            $setArgs = ('/set /subcategory:"{0}" /success:enable /failure:enable' -f $sub)
            $set = Invoke-AuditPol -Arguments $setArgs
            if ($set.ExitCode -ne 0) {
                Write-Log ("auditpol SET FAIL (код {0}): {1}`n{2}" -f $set.ExitCode, $setArgs, $set.Text)
                return $false
            }
        }
        return $true
    }

    $preferRu = Test-RussianUiPreferred

    if ($preferRu) {
        if (Ensure-RuLogonLogoffSubcategories) {
            Write-Log "Проверка аудита (RU): OK для 'Вход в систему' и 'Выход из системы'"
            return
        }

        Write-Log "ВНИМАНИЕ (RU): не удалось автоматически привести аудит подкатегорий 'Вход/выход' к 'Успех и сбой' через auditpol. Скрипт продолжит работу, но часть событий может отсутствовать. Проверьте доменную/локальную GPO (часто мешает централизованный Advanced Audit Policy)."
        return
    }

    if (Ensure-EnLogonLogoffSubcategories) {
        Write-Log "Проверка аудита (EN): OK для Logon/Logoff"
        return
    }

    # Fallback: старый GUID категории Logon/Logoff (Microsoft). Это не "UID пользователя", а GUID категории политики аудита.
    Write-Log "Пробую fallback через GUID категории Logon/Logoff..."
    $guidSet = Invoke-AuditPol -Arguments '/set /category:"{69979849-797A-11D9-BED3-505054503030}" /success:enable /failure:enable'
    if ($guidSet.ExitCode -ne 0) {
        Write-Log ("auditpol GUID SET FAIL (код {0}):`n{1}" -f $guidSet.ExitCode, $guidSet.Text)
    }

    Write-Log "ВНИМАНИЕ: не удалось автоматически настроить аудит входа/выхода через auditpol. Скрипт продолжит работу, но часть событий может отсутствовать. Проверьте политику аудита вручную (локальная/доменная GPO)."
}

function Send-Heartbeat {
    param([switch]$IsStartup = $false)

    $timestamp = Get-Date -Format "dd.MM.yyyy HH:mm:ss"

    if ($IsStartup) {
        $message = "<b>✅ Мониторинг логинов ЗАПУЩЕН</b>`r`n"
        $message += "🖥️ Сервер: $env:COMPUTERNAME`r`n"
        $message += "🕐 Время запуска: $timestamp"
        Send-TelegramMessage -Message $message | Out-Null
        Write-Log "Отправлено уведомление о запуске скрипта"
    } else {
        $timestamp | Out-File -FilePath $HeartbeatFile -Force -Encoding UTF8
    }
}

function Send-StopNotification {
    param([string]$Reason)

    $timestamp = Get-Date -Format "dd.MM.yyyy HH:mm:ss"
    $message = "<b>⚠️ МОНИТОРИНГ ЛОГИНОВ ОСТАНОВЛЕН</b>`r`n"
    $message += "🖥️ Сервер: $env:COMPUTERNAME`r`n"
    $message += "🕐 Время остановки: $timestamp`r`n"
    $message += "📋 Причина: $Reason"

    Send-TelegramMessage -Message $message | Out-Null
    Write-Log "Уведомление об остановке отправлено: $Reason"
}

function Rotate-LogFile {
    try {
        if (Test-Path $LogFile) {
            $backupDate = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
            $backupFileName = "LoginLog_$backupDate.bak"
            $backupFilePath = Join-Path $LogBackupFolder $backupFileName

            Copy-Item -Path $LogFile -Destination $backupFilePath -Force
            Clear-Content -Path $LogFile -Force
            Write-Log "Лог-файл скопирован в бэкап: $backupFilePath"

            $oldBackups = Get-ChildItem -Path $LogBackupFolder -Filter "LoginLog_*.bak" |
                Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$MaxBackupDays) }

            foreach ($oldBackup in $oldBackups) {
                Remove-Item -Path $oldBackup.FullName -Force
                Write-Log "Удален старый бэкап: $($oldBackup.Name)"
            }
            return $true
        }
    } catch {
        Write-Log "Ошибка при ротации лог-файла: $($_.Exception.Message)"
    }
    return $false
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
    $targetRotationTime = Get-Date -Year $currentTime.Year -Month $currentTime.Month -Day $currentTime.Day `
        -Hour $LogRotationHour -Minute $LogRotationMinute -Second 0
    if ($currentTime -ge $targetRotationTime) { $targetRotationTime = $targetRotationTime.AddDays(1) }

    $shouldRotate = $false
    if ($lastRotation -eq $null) { $shouldRotate = $true }
    elseif ($currentTime -ge $targetRotationTime) { $shouldRotate = $true }

    if ($shouldRotate -and (Rotate-LogFile)) {
        $currentTime.ToString("yyyy-MM-dd HH:mm:ss") | Out-File -FilePath $lastRotationFile -Force -Encoding UTF8
    }
    return $targetRotationTime
}

function Cleanup-OldLogs {
    try {
        if (Test-Path $LogBackupFolder) {
            $oldBackups = Get-ChildItem -Path $LogBackupFolder -Filter "LoginLog_*.bak" |
                Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$MaxBackupDays) }
            foreach ($oldBackup in $oldBackups) {
                Remove-Item -Path $oldBackup.FullName -Force
                Write-Log "Удален старый бэкап: $($oldBackup.Name)"
            }
        }
    } catch {
        Write-Log "Ошибка при очистке старых логов: $($_.Exception.Message)"
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
        2  { return "Интерактивный (консоль)" }
        3  { return "Сеть/RDP (Network) (3)" }
        10 { return "Удаленный интерактивный (RDP) (10)" }
        4  { return "Пакетный (Batch)" }
        5  { return "Сервис (Service)" }
        7  { return "Разблокировка (Unlock)" }
        8  { return "Сетевой с явными данными" }
        9  { return "Новые учетные данные" }
        default { return "Тип $LogonType (неизвестный)" }
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

    # DWM/UMFD (иногда приходит как DOMAIN\DWM-8)
    if ($Username -match '(?i)(\\)?DWM-\d+') { return $true }
    if ($Username -match '(?i)(\\)?UMFD-\d+') { return $true }
    if ($Username -like "*$") { return $true }

    # Узкий фильтр: сетевой логон (3) + Advapi + конкретный IP источника
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
        Write-Log "Ошибка при извлечении данных события: $($_.Exception.Message)"
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
        [string]$LogonTypeName
    )

    $message = "<b>"
    if ($EventID -eq 4624) { $message += "✅ УСПЕШНЫЙ ВХОД" }
    elseif ($EventID -eq 4625) { $message += "❌ НЕУДАЧНАЯ ПОПЫТКА" }
    else { $message += "⚠️ СОБЫТИЕ" }
    $message += "</b>`r`n"

    $message += "👤 Пользователь: $Username`r`n"
    $message += "🖥️ Компьютер: $ComputerName`r`n"
    $message += "🌐 IP адрес: $SourceIP`r`n"
    $message += "⚙️ Процесс/Код: $ProcessName`r`n"
    $message += "🔑 Тип входа: $LogonTypeName ($LogonType)`r`n"
    $message += "🕐 Время: $($TimeCreated.ToString('dd.MM.yyyy HH:mm:ss'))`r`n"
    $message += "🔢 Event ID: $EventID"

    return $message
}

function Test-RDGatewayLog {
    try {
        $logExists = Get-WinEvent -ListLog $RDGatewayLogName -ErrorAction SilentlyContinue
        if ($logExists) {
            Write-Log "Журнал RD Gateway доступен: $RDGatewayLogName"
            return $true
        }
    } catch {
        Write-Log "Ошибка при проверке журнала RD Gateway: $($_.Exception.Message)"
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
        Write-Log "Ошибка при извлечении RD Gateway события: $($_.Exception.Message)"
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

    $message = "<b>"
    if ($EventID -eq 302) { $message += "🖥️ УСПЕШНОЕ ПОДКЛЮЧЕНИЕ ЧЕРЕЗ RD GATEWAY" }
    elseif ($EventID -eq 303) { $message += "❌ НЕУДАЧНОЕ ПОДКЛЮЧЕНИЕ ЧЕРЕЗ RD GATEWAY" }
    else { $message += "⚠️ СОБЫТИЕ RD GATEWAY" }
    $message += "</b>`r`n"

    $message += "👤 Пользователь: $Username`r`n"
    $message += "🌐 IP пользователя (внешний): $ExternalIP`r`n"
    $message += "🖥️ IP внутренний: $InternalIP`r`n"
    $message += "🔌 Протокол: $Protocol`r`n"
    if ($EventID -eq 303 -and $ErrorCode -ne "0" -and $ErrorCode -ne "N/A") {
        $message += "⚠️ Код ошибки: $ErrorCode`r`n"
    }
    $message += "🕐 Время: $($TimeCreated.ToString('dd.MM.yyyy HH:mm:ss'))`r`n"
    $message += "🔢 Event ID: $EventID"
    return $message
}

function Send-DailyReport {
    try {
        $quserOutput = & quser 2>$null
        $count = 0
        if ($quserOutput -and $quserOutput.Count -gt 1) { $count = $quserOutput.Count - 1 }
        $message = "<b>📊 ЕЖЕДНЕВНЫЙ ОТЧЕТ</b>`r`n"
        $message += "🖥️ Сервер: $env:COMPUTERNAME`r`n"
        $message += "🕐 Время отчета: $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')`r`n"
        $message += "👥 Активных сессий (quser): $count"
        Send-TelegramMessage -Message $message | Out-Null
        (Get-Date).ToString("yyyy-MM-dd HH:mm:ss") | Out-File -FilePath $LastReportFile -Force -Encoding UTF8
        Write-Log "Ежедневный отчет отправлен"
        return $true
    } catch {
        Write-Log "Ошибка ежедневного отчета: $($_.Exception.Message)"
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
    $target = Get-Date -Year $now.Year -Month $now.Month -Day $now.Day -Hour $DailyReportHour -Minute $DailyReportMinute -Second 0
    if ($now -ge $target) { $target = $target.AddDays(1) }

    $shouldSend = $false
    if ($lastReport -eq $null) { $shouldSend = $true }
    elseif ($now -ge $target) { $shouldSend = $true }
    if ($shouldSend) { Send-DailyReport | Out-Null }

    return $target
}

function Start-LoginMonitor {
    param(
        [int]$MonitorInterval = 5,
        [switch]$MonitorAllEvents = $false,
        [switch]$MonitorInteractiveOnly = $true
    )

    Write-Log "========================================"
    Write-Log "Запуск мониторинга логинов"
    Write-Log "Интерактивные типы: 2,3,10"
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
                            -LogonTypeName $logonTypeName

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
            Write-Log "Ошибка цикла мониторинга: $($_.Exception.Message)"
        }
        Start-Sleep -Seconds $MonitorInterval
    }
}

try {
    Test-TelegramConnection | Out-Null
    Start-LoginMonitor -MonitorInterval 5 -MonitorInteractiveOnly
} catch {
    Write-Log "Критическая ошибка: $($_.Exception.Message)"
    Send-StopNotification -Reason "Критическая ошибка: $($_.Exception.Message)"
    throw
} finally {
    Send-StopNotification -Reason "Скрипт завершил работу"
}

