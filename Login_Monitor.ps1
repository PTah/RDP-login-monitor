<#
.SYNOPSIS
    Мониторинг логинов/попыток входа с уведомлениями в Telegram
.DESCRIPTION
    Отслеживает события входа в систему (Security 4624/4625) и события RD Gateway (302/303),
    отправляет уведомления в Telegram, делает ротацию логов, heartbeat в файл и ежедневный отчет.
.NOTES
    Требуется: PowerShell 5.0+, запуск от администратора.
    Рабочая копия скрипта: C:\ProgramData\RDP-login-monitor\Login_Monitor.ps1
    Логи и бэкапы: C:\ProgramData\RDP-login-monitor\Logs\ (бэкапы 31 день).
    Задачи планировщика: RDP-Login-Monitor (запуск при старте ОС), RDP-Login-Monitor-Watchdog (контроль раз в 5 мин).
    Важное:
    - На некоторых серверах RDP-логин приходит как LogonType=3, поэтому интерактивные типы: 2/3/10.
    - Добавлены исключения шума: DWM-*, UMFD-*, HealthMailbox*, Font Driver Host*, NtLmSsp и др.
    - Heartbeat без дрейфа: используется nextHeartbeatTime (а не "прошло N секунд").
    - Win32_OperatingSystem.ProductType: 1 = рабочая станция (4624/4625 только LogonType 10 + при наличии журнала событие 1149 RCM);
      2/3 = сервер/КД — прежняя логика (типы 2, 3, 10).
    Секреты Telegram (DPAPI LocalMachine): на ЭТОЙ машине, под админом, выполните:
      Add-Type -AssemblyName System.Security
      $p=[Text.Encoding]::UTF8.GetBytes('<токен>')
      [Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect($p,$null,'LocalMachine'))
    Полученную строку вставьте в $TelegramBotTokenProtectedB64 (и аналогично для chat id).
#>

[CmdletBinding()]
param(
    [string]$TelegramBotToken = '<TELEGRAM_BOT_TOKEN>',
    [string]$TelegramChatID = '<TELEGRAM_CHAT_ID>',
    [string]$TelegramBotTokenProtectedB64 = "",
    [string]$TelegramChatIDProtectedB64 = "",
    [switch]$Watchdog,
    [switch]$InstallTasks,
    [switch]$SkipScheduledTaskMaintenance
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Строка из BMP code point (0x....) — в исходнике остается только ASCII, скрипт не ломается
# при скачивании через IWR, если при переносе в строке испортится UTF-8.
function Uc { param([int[]]$C) -join ($C | ForEach-Object { [char]$_ }) }

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

# ============================================
# КОНФИГУРАЦИЯ
# ============================================

# Каталог установки (канонический путь к скрипту и данным)
$script:InstallRoot = [System.IO.Path]::GetFullPath("$env:ProgramData\RDP-login-monitor")
$script:CanonicalScriptName = "Login_Monitor.ps1"
$script:ScheduledTaskNameMain = "RDP-Login-Monitor"
$script:ScheduledTaskNameWatchdog = "RDP-Login-Monitor-Watchdog"
# Один экземпляр: эксклюзивная блокировка файла в InstallRoot (SYSTEM и интерактивный админ — одинаково; Global mutex давал «Отказано в доступе» между контекстами).
$script:MonitorSingletonLockStream = $null

# Версия: пишется в лог и в Telegram. При доменном развёртывании через шару см. DEPLOY.md —
# триггер обновления на клиентах даёт файл version.txt на шаре (его номер можно поднять и без смены
# строки ниже, если правки «мелкие» и вы не хотите менять отображаемую версию в логах).
# Рекомендация: при значимых релизах меняйте и $ScriptVersion, и version.txt одинаково; при только
# исправлениях на шаре — достаточно поднять patch в version.txt (например 1.3.0.1).
$ScriptVersion = "1.3.14"

# Логи (все под InstallRoot)
$LogFile = Join-Path $script:InstallRoot "Logs\login_monitor.log"
$LogBackupFolder = Join-Path $script:InstallRoot "Logs\Backup"
$MaxBackupDays = 31

# Ротация логов (ежедневно)
$LogRotationHour = 0
$LogRotationMinute = 0

# Heartbeat (только файл)
$HeartbeatInterval = 3600
$HeartbeatFile = Join-Path $script:InstallRoot "Logs\last_heartbeat.txt"
$DeployUpdateMarkerFile = Join-Path $script:InstallRoot "deploy_last_update.txt"
# Построчные правила подавления уведомлений Security 4624/4625 (см. ignore.lst.example в репозитории).
$script:IgnoreListPath = Join-Path $script:InstallRoot "ignore.lst"
$script:IgnoreListCache = $null
$script:IgnoreListCacheStampUtc = $null

# Ежедневный отчет
$DailyReportHour = 9
$DailyReportMinute = 0
$LastReportFile = Join-Path $script:InstallRoot "Logs\last_daily_report.txt"

# RD Gateway
$EnableRDGatewayMonitoring = $true
$RDGatewayLogName = "Microsoft-Windows-TerminalServices-Gateway/Operational"
$RDGatewayEvents = @(302, 303)

# RDP Remote Connection Manager (workstations): User authentication succeeded — событие 1149
$RcmLogName = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"
$RcmEventId = 1149

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

if (!(Test-Path -LiteralPath $script:InstallRoot)) {
    New-Item -ItemType Directory -Path $script:InstallRoot -Force | Out-Null
}
$LogDir = Split-Path $LogFile -Parent
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
if (!(Test-Path $LogBackupFolder)) { New-Item -ItemType Directory -Path $LogBackupFolder -Force | Out-Null }

# UTF-8 с BOM: иначе часть просмотрщиков (FAR и др.) открывает лог как ANSI/OEM и показывает "кракозябры".
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

function Get-RdpMonitorThisScriptPath {
    $p = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($p)) { $p = $MyInvocation.MyCommand.Path }
    # При запуске дочернего процесса через Start-Process иногда нет PSCommandPath — используем каталог скрипта.
    if ([string]::IsNullOrWhiteSpace($p) -and -not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $p = Join-Path $PSScriptRoot $script:CanonicalScriptName
    }
    if ([string]::IsNullOrWhiteSpace($p)) { return $null }
    return [System.IO.Path]::GetFullPath($p)
}

function Get-RdpMonitorScriptPathFromCommandLine {
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return $null }
    $m = [regex]::Match($CommandLine, '(?i)-File\s+"([^"]+)"')
    if ($m.Success) {
        try { return [System.IO.Path]::GetFullPath($m.Groups[1].Value) } catch { return $null }
    }
    $m2 = [regex]::Match($CommandLine, '(?i)-File\s+(\S+)')
    if ($m2.Success) {
        try { return [System.IO.Path]::GetFullPath($m2.Groups[1].Value) } catch { return $null }
    }
    return $null
}

function Test-RdpMonitorCommandLineIsWatchdog {
    param([string]$CommandLine)
    return ($CommandLine -match '(?i)(^|\s)-Watchdog(\s|$)')
}

function Get-RdpLoginMonitorProcessInfos {
    $result = [System.Collections.Generic.List[object]]::new()
    try {
        $procs = Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe' OR Name = 'pwsh.exe'" -ErrorAction Stop
        foreach ($proc in $procs) {
            $cl = [string]$proc.CommandLine
            if ($cl -notmatch 'Login_Monitor\.ps1') { continue }
            $scriptPath = Get-RdpMonitorScriptPathFromCommandLine -CommandLine $cl
            $isWd = Test-RdpMonitorCommandLineIsWatchdog -CommandLine $cl
            $result.Add([pscustomobject]@{
                ProcessId = [int]$proc.ProcessId
                ScriptPath = $scriptPath
                IsWatchdog = [bool]$isWd
                CommandLine = $cl
            }) | Out-Null
        }
    } catch {
        Write-Log "Предупреждение: перечень процессов Win32 (миграция экземпляров): $($_.Exception.Message)"
    }
    return @($result)
}

function Invoke-RdpMonitorProcessMigrationAndRelaunch {
    $canonicalScript = [System.IO.Path]::GetFullPath((Join-Path $script:InstallRoot $script:CanonicalScriptName))
    $thisPath = Get-RdpMonitorThisScriptPath
    if ($null -eq $thisPath) {
        Write-Log "Не удалось определить путь к текущему скрипту — продолжение невозможно."
        exit 1
    }

    $infos = @(Get-RdpLoginMonitorProcessInfos)
    $others = @($infos | Where-Object { $_.ProcessId -ne $PID })

    foreach ($o in $others) {
        if ($o.IsWatchdog) { continue }
        if ($null -eq $o.ScriptPath) { continue }
        $p = [System.IO.Path]::GetFullPath($o.ScriptPath)
        if ($p -ne $canonicalScript) {
            Write-Log "Останавливаю экземпляр монитора из другого каталога (PID $($o.ProcessId)): $p"
            Stop-Process -Id $o.ProcessId -Force -ErrorAction SilentlyContinue
        }
    }

    if ($thisPath -ne $canonicalScript) {
        if (-not (Test-Path -LiteralPath $canonicalScript)) {
            Write-Log "ОШИБКА: Канонический скрипт не найден: $canonicalScript. Скопируйте Login_Monitor.ps1 в $($script:InstallRoot) и запустите снова."
            exit 1
        }
        Write-Log "Текущий запуск из $thisPath — передаю работу каноническому файлу $canonicalScript и завершаюсь."
        Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $canonicalScript
        ) -WindowStyle Hidden
        exit 0
    }

}

function Lock-RdpMonitorSingleInstance {
    # Эксклюзивный поток (FileShare.None): пока монитор работает, файл нельзя удалить вручную —
    # это нормально. DeleteOnClose: при любом завершении процесса ОС удалит файл при закрытии
    # дескриптора (в т.ч. при «Снять задачу»), без «вечных» сирот на диске.
    $lockPath = Join-Path $script:InstallRoot '.login_monitor_single_instance.lock'
    try {
        $script:MonitorSingletonLockStream = New-Object System.IO.FileStream(
            $lockPath,
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None,
            4096,
            [System.IO.FileOptions]::DeleteOnClose
        )
    } catch [System.IO.IOException] {
        Write-Log "Экземпляр монитора уже активен (блокировка файла). Выход без дублирования."
        exit 0
    } catch {
        Write-Log "Не удалось занять блокировку экземпляра (${lockPath}): $($_.Exception.Message)"
        exit 1
    }
}

function Release-RdpMonitorSingletonLock {
    $lockPath = Join-Path $script:InstallRoot '.login_monitor_single_instance.lock'
    if ($null -ne $script:MonitorSingletonLockStream) {
        try {
            $script:MonitorSingletonLockStream.Close()
        } catch { }
        try {
            $script:MonitorSingletonLockStream.Dispose()
        } catch { }
        $script:MonitorSingletonLockStream = $null
    }
    if (Test-Path -LiteralPath $lockPath) {
        try {
            Remove-Item -LiteralPath $lockPath -Force -ErrorAction Stop
        } catch {
            try {
                [System.IO.File]::Delete($lockPath)
            } catch { }
        }
    }
}

function Get-RdpMonitorPowerShellExe {
    return "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
}

function Test-RdpMonitorScheduledTaskMatches {
    param(
        [Parameter(Mandatory = $true)][string]$TaskName,
        [Parameter(Mandatory = $true)][string]$ExpectedExe,
        [Parameter(Mandatory = $true)][string]$ExpectedArguments
    )
    try {
        $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop | Select-Object -First 1
        $a = @($t.Actions)[0]
        if ($null -eq $a) { return $false }
        $exe = [string]$a.Execute
        $arg = [string]$a.Arguments
        return (($exe.Trim() -eq $ExpectedExe.Trim()) -and ($arg.Trim() -eq $ExpectedArguments.Trim()))
    } catch {
        return $false
    }
}

function Register-RdpMonitorScheduledTasksCore {
    Write-Log "Register-RdpMonitorScheduledTasksCore: ветка v$ScriptVersion (watchdog через schtasks /SC MINUTE, без CIM RepetitionInterval)."
    $psExe = Get-RdpMonitorPowerShellExe
    $canonicalScript = [System.IO.Path]::GetFullPath((Join-Path $script:InstallRoot $script:CanonicalScriptName))
    if (-not (Test-Path -LiteralPath $canonicalScript)) {
        Write-Log "Задачи планировщика не созданы: нет файла $canonicalScript"
        return
    }

    $argMain = "-NoProfile -ExecutionPolicy Bypass -File `"$canonicalScript`""
    $argWd = "-NoProfile -ExecutionPolicy Bypass -File `"$canonicalScript`" -Watchdog"

    $actionMain = New-ScheduledTaskAction -Execute $psExe -Argument $argMain
    $triggerBoot = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

    Register-ScheduledTask -TaskName $script:ScheduledTaskNameMain -Action $actionMain -Trigger $triggerBoot `
        -Principal $principal -Settings $settings -Force | Out-Null
    Write-Log "Задача планировщика: $($script:ScheduledTaskNameMain) (запуск при старте ОС)."

    # Watchdog только через schtasks. /Delete при отсутствии задачи пишет в stderr — при $ErrorActionPreference Stop раньше рвал скрипт.
    $schtasksExe = Join-Path $env:SystemRoot 'System32\schtasks.exe'
    $delErrAction = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'SilentlyContinue'
        & $schtasksExe /Delete /TN $script:ScheduledTaskNameWatchdog /F 2>$null | Out-Null
    } finally {
        $ErrorActionPreference = $delErrAction
    }

    $trForSch = "`"$psExe`" $argWd"
    $schOut = & $schtasksExe /Create /F /RU SYSTEM /RL HIGHEST /SC MINUTE /MO 5 /TN $script:ScheduledTaskNameWatchdog /TR $trForSch 2>&1
    foreach ($line in @($schOut)) {
        Write-Log "schtasks watchdog: $line"
    }
    Write-Log "Задача планировщика: $($script:ScheduledTaskNameWatchdog) (schtasks, каждые 5 минут, контроль процесса)."

    # Не ждём перезагрузку: сразу запускаем основную задачу.
    $runMainEa = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'SilentlyContinue'
        $runMainOut = & $schtasksExe /Run /TN $script:ScheduledTaskNameMain 2>&1
        foreach ($line in @($runMainOut)) {
            if ($null -ne $line -and "$line".Trim().Length -gt 0) {
                Write-Log "schtasks main /Run: $line"
            }
        }
    } finally {
        $ErrorActionPreference = $runMainEa
    }
    Write-Log "Немедленный прогон основной задачи запрошен (schtasks /Run)."

    # Первый запуск watchdog по расписанию может быть почти через 5 мин — ставим одноразовый прогон в очередь.
    $runEa = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'SilentlyContinue'
        $runOut = & $schtasksExe /Run /TN $script:ScheduledTaskNameWatchdog 2>&1
        foreach ($line in @($runOut)) {
            if ($null -ne $line -and "$line".Trim().Length -gt 0) {
                Write-Log "schtasks watchdog /Run: $line"
            }
        }
    } finally {
        $ErrorActionPreference = $runEa
    }
    Write-Log "Немедленный прогон watchdog запрошен (schtasks /Run)."
}

function Ensure-RdpMonitorScheduledTasks {
    if ($SkipScheduledTaskMaintenance) {
        Write-Log "Обслуживание задач планировщика пропущено (-SkipScheduledTaskMaintenance)."
        return
    }
    $psExe = Get-RdpMonitorPowerShellExe
    $canonicalScript = [System.IO.Path]::GetFullPath((Join-Path $script:InstallRoot $script:CanonicalScriptName))
    $argMain = "-NoProfile -ExecutionPolicy Bypass -File `"$canonicalScript`""
    $argWd = "-NoProfile -ExecutionPolicy Bypass -File `"$canonicalScript`" -Watchdog"

    $needMain = -not (Test-RdpMonitorScheduledTaskMatches -TaskName $script:ScheduledTaskNameMain -ExpectedExe $psExe -ExpectedArguments $argMain)
    $needWd = -not (Test-RdpMonitorScheduledTaskMatches -TaskName $script:ScheduledTaskNameWatchdog -ExpectedExe $psExe -ExpectedArguments $argWd)

    if (-not $needMain -and -not $needWd) {
        Write-Log "Задачи планировщика ($($script:ScheduledTaskNameMain), $($script:ScheduledTaskNameWatchdog)) соответствуют каноническим путям."
        return
    }

    if ($needMain) { Write-Log "Требуется обновить или создать задачу: $($script:ScheduledTaskNameMain)" }
    if ($needWd) { Write-Log "Требуется обновить или создать задачу: $($script:ScheduledTaskNameWatchdog)" }

    Register-RdpMonitorScheduledTasksCore
}

function Start-RdpMonitorWatchdogMain {
    $watchdogLog = Join-Path $script:InstallRoot "Logs\watchdog.log"
    $canonicalScript = [System.IO.Path]::GetFullPath((Join-Path $script:InstallRoot $script:CanonicalScriptName))
    function Write-WdLog {
        param([string]$Message)
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $line = "$timestamp - $Message" + [Environment]::NewLine
        try {
            [System.IO.File]::AppendAllText($watchdogLog, $line, $script:Utf8BomEncoding)
        } catch { }
        Write-Host ($line.TrimEnd("`r`n"))
    }

    Write-WdLog "Watchdog (версия $ScriptVersion): проверка экземпляра монитора. Ожидаемый скрипт: $canonicalScript"

    try {
        $mainRunning = $false
        $infos = @(Get-RdpLoginMonitorProcessInfos)
        foreach ($info in $infos) {
            if ($info.IsWatchdog) { continue }
            if ($null -eq $info.ScriptPath) { continue }
            if ([System.IO.Path]::GetFullPath($info.ScriptPath) -ne $canonicalScript) { continue }
            $mainRunning = $true
            break
        }

        if (-not $mainRunning) {
            Write-WdLog "Монитор не найден — запуск $canonicalScript"
            $psExeWd = Get-RdpMonitorPowerShellExe
            $started = Start-Process -FilePath $psExeWd -WorkingDirectory $script:InstallRoot -ArgumentList @(
                '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $canonicalScript
            ) -WindowStyle Hidden -PassThru
            Write-WdLog "Монитор: создан процесс PID=$($started.Id)."
            Start-Sleep -Seconds 5
            $still = Get-Process -Id $started.Id -ErrorAction SilentlyContinue
            if (-not $still) {
                Write-WdLog "ПРЕДУПРЕЖДЕНИЕ: процесс монитора PID $($started.Id) завершился за несколько секунд — см. конец $script:LogFile (ошибка до цикла мониторинга)."
            } else {
                Write-WdLog "Монитор: процесс PID $($started.Id) ещё работает после старта."
            }
        } else {
            Write-WdLog "Монитор работает (канонический экземпляр найден)."
        }
    } catch {
        Write-WdLog "Ошибка watchdog: $($_.Exception.Message)"
        exit 1
    }
    exit 0
}

# --- Учётные данные Telegram (открытый текст или DPAPI Base64) ---
if (-not [string]::IsNullOrWhiteSpace($TelegramBotTokenProtectedB64)) {
    try {
        $TelegramBotToken = Unprotect-RdpMonitorDpapiB64 -Base64 $TelegramBotTokenProtectedB64
    } catch {
        Write-Host "Ошибка расшифровки TelegramBotToken (DPAPI): $($_.Exception.Message)"
        exit 1
    }
}
if (-not [string]::IsNullOrWhiteSpace($TelegramChatIDProtectedB64)) {
    try {
        $TelegramChatID = Unprotect-RdpMonitorDpapiB64 -Base64 $TelegramChatIDProtectedB64
    } catch {
        Write-Host "Ошибка расшифровки TelegramChatID (DPAPI): $($_.Exception.Message)"
        exit 1
    }
}
if ($TelegramBotToken -eq '<TELEGRAM_BOT_TOKEN>') { $TelegramBotToken = "" }
if ($TelegramChatID -eq '<TELEGRAM_CHAT_ID>') { $TelegramChatID = "" }

if ($Watchdog) {
    Start-RdpMonitorWatchdogMain
    exit 0
}

if ($InstallTasks) {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Log "InstallTasks: нужны права администратора."
        exit 1
    }
    Register-RdpMonitorScheduledTasksCore
    Write-Log "InstallTasks: задачи планировщика обновлены."
    exit 0
}

function ConvertTo-TelegramHtml {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
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
    Write-Log "ОШИБКА: Скрипт должен быть запущен от имени администратора! (версия $ScriptVersion)"
    exit 1
}
Write-Log "Скрипт запущен с правами администратора, версия $ScriptVersion"

Invoke-RdpMonitorProcessMigrationAndRelaunch
Lock-RdpMonitorSingleInstance
Ensure-RdpMonitorScheduledTasks

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

$script:IsWorkstation = $false
$script:OsInstallKindLabel = ""

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

    # Do NOT use Get-Culture/PSUICulture: OS can be "ru" while auditpol stays English (Hyper-V, etc.).
    # Only trust actual auditpol /list output.
    function Test-RussianUiPreferred {
        $r = Invoke-AuditPol -Arguments '/list /subcategory:*'
        if ($r.ExitCode -ne 0) { return $false }
        $ax = Uc @(0x0412,0x0445,0x043E,0x0434,0x002F,0x0432,0x044B,0x0445,0x043E,0x0434)
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
        $category = Uc @(0x0412,0x0445,0x043E,0x0434,0x002F,0x0432,0x044B,0x0445,0x043E,0x0434)
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
        Write-Log "Russian category names not accepted or failed; trying English Logon/Logoff (auditpol language can differ from OS UI)."
    }

    if (Ensure-EnLogonLogoffSubcategories) {
        Write-Log "Audit policy (EN): OK for Logon/Logoff (English auditpol output)."
        return
    }

    # Logon/Logoff category GUID (not a user id).
    Write-Log "Trying Logon/Logoff category set via known GUID (fallback)..."
    $logonLogoffCategoryGuid = "69979849-797A-11D9-BED3-505054503030"
    $guidSet = Invoke-AuditPol -Arguments ("/set /category:`"$logonLogoffCategoryGuid`" /success:enable /failure:enable")
    if ($guidSet.ExitCode -ne 0) {
        Write-Log ("auditpol GUID SET FAIL (code {0}):`n{1}" -f $guidSet.ExitCode, $guidSet.Text)
    }

    Write-Log "WARNING: could not configure logon/logoff auditing via auditpol automatically. The script will continue; check audit policy in local/domain GPO."
}

function Test-RDSDeploymentPresent {
    # Узел только с RD Gateway (RDS-Gateway и т.п.) не считаем «полноценным RDS по сессиям» —
    # для шлюза отдельное сообщение в Telegram (журнал Gateway, 302/303 к целевым ПК).
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

function Get-OsInstallKind {
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $pt = [int]$os.ProductType
        # 1 Workstation, 2 Domain Controller, 3 Server (member)
        $label = switch ($pt) {
            1 { 'Workstation' }
            2 { 'Domain Controller' }
            3 { 'Server' }
            default { "ProductType=$pt" }
        }
        return [pscustomobject]@{
            ProductType   = $pt
            IsWorkstation = ($pt -eq 1)
            Label         = $label
        }
    } catch {
        Write-Log "Определение SKU ОС не удалось: $($_.Exception.Message); считаем Server"
        return [pscustomobject]@{
            ProductType   = 3
            IsWorkstation = $false
            Label         = 'Unknown (assume Server)'
        }
    }
}

function Test-RcmLogAvailable {
    try {
        $logExists = Get-WinEvent -ListLog $RcmLogName -ErrorAction SilentlyContinue
        return [bool]$logExists
    } catch {
        return $false
    }
}

function Get-Rcm1149EventInfo {
    param($Event)
    $eventData = @{
        TimeCreated = $Event.TimeCreated
        Username = "-"
        ClientIP = "-"
    }
    try {
        $map = Get-EventDataMap -Event $Event
        $user = Get-FirstNonEmptyMapValue -DataMap $map -Keys @(
            "TargetUser","User","Domain User","Param1","AccountName","ConnectionUser","SubjectUserName"
        )
        $ip = Get-FirstNonEmptyMapValue -DataMap $map -Keys @(
            "ClientIP","Client Address","IpAddress","Ip","Param3","Address","CallingStationId"
        )
        if (-not [string]::IsNullOrWhiteSpace($user)) { $eventData.Username = [string]$user }
        if (-not [string]::IsNullOrWhiteSpace($ip)) { $eventData.ClientIP = [string]$ip }

        if ($eventData.Username -eq '-' -and $Event.Properties.Count -gt 0) {
            $eventData.Username = [string]$Event.Properties[0].Value
        }
        if ($eventData.ClientIP -eq '-') {
            if ($Event.Properties.Count -gt 2) {
                $eventData.ClientIP = [string]$Event.Properties[2].Value
            } elseif ($Event.Properties.Count -gt 1) {
                $eventData.ClientIP = [string]$Event.Properties[1].Value
            }
        }
    } catch {
        Write-Log "Ошибка разбора события RCM 1149: $($_.Exception.Message)"
    }
    return $eventData
}

function Format-Rcm1149Event {
    param(
        [string]$Username,
        [string]$ClientIP,
        [datetime]$TimeCreated,
        [string]$SecurityLogComputerName
    )
    $logHost = $SecurityLogComputerName
    if ([string]::IsNullOrWhiteSpace($logHost)) { $logHost = $env:COMPUTERNAME }
    $hUser = (ConvertTo-TelegramHtml $Username)
    $hIp = (ConvertTo-TelegramHtml $ClientIP)
    $hLog = (ConvertTo-TelegramHtml $logHost)
    $hTime = (ConvertTo-TelegramHtml ($TimeCreated.ToString('dd.MM.yyyy HH:mm:ss')))
    $message = "<b>🔑 RDP: успешная аутентификация (1149)</b>`r`n"
    $message += "👤 Пользователь: $hUser`r`n"
    $message += "🏢 Узел: $hLog`r`n"
    $message += "🌐 Клиент (IP): $hIp`r`n"
    $message += "🕐 Время: $hTime`r`n"
    $message += "🔢 Event ID: 1149 (RemoteConnectionManager)"
    return $message
}

function Send-Heartbeat {
    param([switch]$IsStartup = $false)

    $timestamp = Get-Date -Format "dd.MM.yyyy HH:mm:ss"
    $hHost = (ConvertTo-TelegramHtml $env:COMPUTERNAME)

    function Get-DeployUpdateMarker {
        $info = [pscustomobject]@{
            Version = $null
            UpdatedAt = $null
            PendingStartupNotice = $false
        }
        if (-not (Test-Path -LiteralPath $DeployUpdateMarkerFile)) { return $info }
        try {
            $lines = @((Get-Content -LiteralPath $DeployUpdateMarkerFile -ErrorAction Stop) | Where-Object { $_ -match '\S' })
            foreach ($ln in $lines) {
                $parts = $ln -split '=', 2
                if ($parts.Count -ne 2) { continue }
                $k = ($parts[0]).Trim()
                $v = ($parts[1]).Trim()
                switch ($k) {
                    'Version' { $info.Version = $v }
                    'UpdatedAt' { $info.UpdatedAt = $v }
                    'PendingStartupNotice' { $info.PendingStartupNotice = ($v -eq '1' -or $v -ieq 'true') }
                }
            }
        } catch { }
        return $info
    }

    function Set-DeployUpdateMarkerPendingOff {
        param([pscustomobject]$Marker)
        try {
            $ver = if ([string]::IsNullOrWhiteSpace($Marker.Version)) { '' } else { $Marker.Version }
            $upd = if ([string]::IsNullOrWhiteSpace($Marker.UpdatedAt)) { '' } else { $Marker.UpdatedAt }
            $content = @(
                "Version=$ver"
                "UpdatedAt=$upd"
                "PendingStartupNotice=0"
            ) -join "`r`n"
            Write-TextFileUtf8Bom -Path $DeployUpdateMarkerFile -Text $content
        } catch { }
    }

    if ($IsStartup) {
        $message = "<b>✅ Мониторинг логинов ЗАПУЩЕН</b>`r`n"
        $message += "🏷️ Версия скрипта: $(ConvertTo-TelegramHtml $ScriptVersion)"
        $upd = Get-DeployUpdateMarker
        if ($upd.PendingStartupNotice -and $upd.Version -eq $ScriptVersion -and -not [string]::IsNullOrWhiteSpace($upd.UpdatedAt)) {
            $message += " (обновлён $(ConvertTo-TelegramHtml $upd.UpdatedAt))"
            Set-DeployUpdateMarkerPendingOff -Marker $upd
        }
        $message += "`r`n"
        $message += "🖥️ Сервер: $hHost`r`n"
        $message += "🕐 Время запуска: $timestamp"
        if ($script:OsInstallKindLabel) {
            $message += "`r`n💻 <b>Тип установки:</b> $(ConvertTo-TelegramHtml $script:OsInstallKindLabel)"
        }
        if ($script:IsWorkstation) {
            $message += "`r`n📌 <b>Режим:</b> рабочая станция — Security 4624/4625 только LogonType 10 (RDP); при наличии журнала — также 1149 (Remote Connection Manager)."
        } else {
            $message += "`r`n📌 <b>Режим:</b> сервер — Security 4624/4625, типы входа 2, 3, 10."
        }
        if (Test-RDSDeploymentPresent) {
            $message += "`r`n🔐 <b>RDS (хост сессий):</b> обнаружены компоненты RDS помимо чистого шлюза — в мониторинг входят входы по RDP/RDS на этом узле (Security 4624/4625, типы входа по настройке скрипта)."
        }
        if ($EnableRDGatewayMonitoring) {
            try {
                $gwLog = Get-WinEvent -ListLog $RDGatewayLogName -ErrorAction SilentlyContinue
                if ($gwLog) {
                    $message += "`r`n🌐 <b>RD Gateway:</b> журнал шлюза доступен — дополнительно фиксируются подключения пользователей к <b>внутренним целевым компьютерам</b> через RD Gateway (события 302/303 в журнале шлюза)."
                }
            } catch { }
        }
        Send-TelegramMessage -Message $message | Out-Null
        Write-Log "Отправлено уведомление о запуске скрипта"
    } else {
        Write-TextFileUtf8Bom -Path $HeartbeatFile -Text $timestamp
    }
}

function Send-StopNotification {
    param([string]$Reason)

    $timestamp = Get-Date -Format "dd.MM.yyyy HH:mm:ss"
    $hHost = (ConvertTo-TelegramHtml $env:COMPUTERNAME)
    $hReason = (ConvertTo-TelegramHtml $Reason)
    $message = "<b>⚠️ МОНИТОРИНГ ЛОГИНОВ ОСТАНОВЛЕН</b>`r`n"
    $message += "🖥️ Сервер: $hHost`r`n"
    $message += "🕐 Время остановки: $timestamp`r`n"
    $message += "📋 Причина: $hReason"

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
            # После Clear-Content файл пустой без BOM — восстановим UTF-8 BOM для корректного просмотра в FAR/редакторах
            Ensure-FileStartsWithUtf8Bom -Path $LogFile
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

function Test-RdpMonitorUsernameMatchesToken {
    param([string]$Username, [string]$Token)
    if ([string]::IsNullOrWhiteSpace($Username) -or [string]::IsNullOrWhiteSpace($Token)) { return $false }
    if ($Username -ieq $Token) { return $true }
    if ($Token.Contains('\')) {
        return ($Username -ieq $Token)
    }
    $i = $Username.LastIndexOf('\')
    if ($i -ge 0 -and $i -lt ($Username.Length - 1)) {
        $sam = $Username.Substring($i + 1)
        if ($sam -ieq $Token) { return $true }
    }
    return $false
}

function Parse-RdpMonitorIgnoreListLine {
    param([string]$RawLine)
    $line = ([string]$RawLine).Trim()
    if ($line.Length -eq 0) { return $null }
    if ($line[0] -eq '#' -or $line[0] -eq ';') { return $null }
    if ($line.StartsWith([char]0xFEFF)) { $line = $line.TrimStart([char]0xFEFF) }

    if ($line -notmatch ':') {
        return [pscustomobject]@{ Kind = 'Any'; Value = $line }
    }

    $idx = $line.IndexOf(':')
    $left = $line.Substring(0, $idx).Trim()
    $right = $line.Substring($idx + 1).Trim()
    if ([string]::IsNullOrWhiteSpace($right)) { return $null }

    if ($left -match '(?i)(рабоч|workstation|wks)') {
        return [pscustomobject]@{ Kind = 'Workstation'; Value = $right }
    }
    if ($left -match '(?i)(польз|username|subject|account|target\s*user|\buser\b)') {
        return [pscustomobject]@{ Kind = 'User'; Value = $right }
    }
    if ($left -match '(?i)(\bip\b|ip\s*адрес|ipaddress|адрес\s*ip)') {
        return [pscustomobject]@{ Kind = 'Ip'; Value = $right }
    }

    return [pscustomobject]@{ Kind = 'Any'; Value = $right }
}

function Get-RdpMonitorIgnoreListEntries {
    if (-not (Test-Path -LiteralPath $script:IgnoreListPath)) {
        $script:IgnoreListCache = @()
        $script:IgnoreListCacheStampUtc = $null
        return $script:IgnoreListCache
    }
    try {
        $fi = Get-Item -LiteralPath $script:IgnoreListPath -ErrorAction Stop
        $stamp = $fi.LastWriteTimeUtc
        if ($null -ne $script:IgnoreListCache -and $script:IgnoreListCacheStampUtc -eq $stamp) {
            return $script:IgnoreListCache
        }
        $entries = [System.Collections.Generic.List[object]]::new()
        foreach ($ln in (Get-Content -LiteralPath $script:IgnoreListPath -Encoding UTF8 -ErrorAction Stop)) {
            $e = Parse-RdpMonitorIgnoreListLine -RawLine $ln
            if ($null -ne $e) { $entries.Add($e) | Out-Null }
        }
        $script:IgnoreListCache = @($entries)
        $script:IgnoreListCacheStampUtc = $stamp
        $arr = $script:IgnoreListCache
        $nIp = @($arr | Where-Object { $_.Kind -eq 'Ip' }).Count
        $nUser = @($arr | Where-Object { $_.Kind -eq 'User' }).Count
        $nWks = @($arr | Where-Object { $_.Kind -eq 'Workstation' }).Count
        $nAny = @($arr | Where-Object { $_.Kind -eq 'Any' }).Count
        $nTotal = $arr.Count
        if ($nTotal -eq 0) {
            Write-Log "ignore.lst обновлён: список правил пуст, игнорирование по файлу для Security 4624/4625 не задаётся."
        } else {
            Write-Log ("ignore.lst обновлён: добавлено игнорирование событий 4624/4625 по IP ({0}), пользователю ({1}), рабочей станции ({2}); универсальных правил ({3}). Всего записей: {4}." -f $nIp, $nUser, $nWks, $nAny, $nTotal)
        }
        return $script:IgnoreListCache
    } catch {
        Write-Log "Предупреждение: не удалось прочитать ignore.lst: $($_.Exception.Message)"
        $script:IgnoreListCache = @()
        $script:IgnoreListCacheStampUtc = $null
        return $script:IgnoreListCache
    }
}

function Test-RdpMonitorIgnoreListMatch {
    param(
        [string]$Username,
        [string]$ComputerName,
        [string]$SourceIP
    )
    $entries = @(Get-RdpMonitorIgnoreListEntries)
    if ($entries.Count -eq 0) { return $false }

    foreach ($e in $entries) {
        $v = [string]$e.Value
        if ([string]::IsNullOrWhiteSpace($v)) { continue }

        switch ($e.Kind) {
            'User' {
                if (Test-RdpMonitorUsernameMatchesToken -Username $Username -Token $v) { return $true }
            }
            'Workstation' {
                if (-not [string]::IsNullOrWhiteSpace($ComputerName) -and $ComputerName -ne '-' -and ($ComputerName -ieq $v)) {
                    return $true
                }
            }
            'Ip' {
                if (-not [string]::IsNullOrWhiteSpace($SourceIP) -and $SourceIP -ne '-' -and ($SourceIP -ieq $v)) {
                    return $true
                }
            }
            'Any' {
                if (Test-RdpMonitorStringLooksLikeIPv4 $v) {
                    if (-not [string]::IsNullOrWhiteSpace($SourceIP) -and $SourceIP -ne '-' -and ($SourceIP -ieq $v)) {
                        return $true
                    }
                    continue
                }
                if ($v.Contains('\')) {
                    if (Test-RdpMonitorUsernameMatchesToken -Username $Username -Token $v) { return $true }
                    continue
                }
                if (-not [string]::IsNullOrWhiteSpace($ComputerName) -and $ComputerName -ne '-' -and ($ComputerName -ieq $v)) {
                    return $true
                }
                if (Test-RdpMonitorUsernameMatchesToken -Username $Username -Token $v) { return $true }
            }
        }
    }
    return $false
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

    if ($EventID -in 4624, 4625) {
        if (Test-RdpMonitorIgnoreListMatch -Username $Username -ComputerName $ComputerName -SourceIP $SourceIP) {
            return $true
        }
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
    if ($EventID -eq 4624) { $message += "✅ УСПЕШНЫЙ ВХОД" }
    elseif ($EventID -eq 4625) { $message += "❌ НЕУДАЧНАЯ ПОПЫТКА" }
    else { $message += "⚠️ СОБЫТИЕ" }
    $message += "</b>`r`n"

    $message += "👤 Пользователь: $hUser`r`n"
    $message += "🏢 Сервер (журнал Security): $hLog`r`n"
    $message += "🖥️ Рабочая станция (клиент из события): $hWkst`r`n"
    $message += "🌐 IP адрес: $hIp`r`n"
    $message += "⚙️ Процесс/Код: $hProc`r`n"
    $message += "🔑 Тип входа: $hLtName ($LogonType)`r`n"
    $message += "🕐 Время: $hTime`r`n"
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

function Test-RdpMonitorStringLooksLikeIPv4 {
    param([string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
    $t = $Value.Trim()
    return [bool]($t -match '^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$')
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
        $map = Get-EventDataMap -Event $Event
        $lc = @{}
        foreach ($k in $map.Keys) {
            try { $lc[$k.ToLowerInvariant()] = $map[$k] } catch { }
        }
        function Get-RdpGwMapVal([string[]]$Keys) {
            foreach ($key in $Keys) {
                $lk = $key.ToLowerInvariant()
                if (-not $lc.ContainsKey($lk)) { continue }
                $v = $lc[$lk]
                if (-not [string]::IsNullOrWhiteSpace($v)) { return [string]$v }
            }
            return $null
        }

        $u = Get-RdpGwMapVal @('username','user','authusername')
        $ext = Get-RdpGwMapVal @('clientaddress','clientip','ipaddress','address','remoteaddress','sourceaddress')
        $int = Get-RdpGwMapVal @('targetserver','targetname','resource','server','internaladdress','destinationaddress','targetaddress','devicename','computername')
        $proto = Get-RdpGwMapVal @('protocol','transport','connectionprotocol','tunneltype')
        $err = Get-RdpGwMapVal @('errorcode','statuscode','error','resultcode','status')

        if ($u) { $eventData.Username = $u }
        if ($ext) { $eventData.ExternalIP = $ext }
        if ($int) { $eventData.InternalIP = $int }
        if ($proto) { $eventData.Protocol = $proto }
        if ($err) { $eventData.ErrorCode = $err }

        $fillFromProps = ($lc.Count -eq 0) -or (
            (($eventData.InternalIP -eq 'N/A' -or [string]::IsNullOrWhiteSpace($eventData.InternalIP)) -and (
                    ($eventData.Protocol -eq 'N/A' -or [string]::IsNullOrWhiteSpace($eventData.Protocol)) -or
                    (Test-RdpMonitorStringLooksLikeIPv4 $eventData.Protocol)
                ))
        )

        if ($fillFromProps) {
            switch ($Event.Id) {
                302 {
                    if ($Event.Properties.Count -gt 0) { $eventData.Username = [string]$Event.Properties[0].Value }
                    if ($Event.Properties.Count -gt 1) { $eventData.ExternalIP = [string]$Event.Properties[1].Value }
                    if ($Event.Properties.Count -gt 2) {
                        $p2 = [string]$Event.Properties[2].Value
                        $p3 = if ($Event.Properties.Count -gt 3) { [string]$Event.Properties[3].Value } else { '' }
                        $p4 = if ($Event.Properties.Count -gt 4) { [string]$Event.Properties[4].Value } else { '' }
                        if ([string]::IsNullOrWhiteSpace($p2) -and (Test-RdpMonitorStringLooksLikeIPv4 $p3)) {
                            $eventData.InternalIP = $p3.Trim()
                            if (-not [string]::IsNullOrWhiteSpace($p4)) {
                                $eventData.Protocol = $p4.Trim()
                            }
                        } else {
                            $eventData.InternalIP = $p2.Trim()
                            if (-not [string]::IsNullOrWhiteSpace($p3)) { $eventData.Protocol = $p3.Trim() }
                        }
                    }
                    $eventData.ErrorCode = "0"
                }
                303 {
                    if ($Event.Properties.Count -gt 0) { $eventData.Username = [string]$Event.Properties[0].Value }
                    if ($Event.Properties.Count -gt 1) { $eventData.ExternalIP = [string]$Event.Properties[1].Value }
                    if ($Event.Properties.Count -gt 2) {
                        $p2 = [string]$Event.Properties[2].Value
                        $p3 = if ($Event.Properties.Count -gt 3) { [string]$Event.Properties[3].Value } else { '' }
                        if ([string]::IsNullOrWhiteSpace($p2) -and (Test-RdpMonitorStringLooksLikeIPv4 $p3)) {
                            $eventData.InternalIP = $p3.Trim()
                            if ($Event.Properties.Count -gt 4) { $eventData.ErrorCode = [string]$Event.Properties[4].Value }
                            if ($Event.Properties.Count -gt 5) { $eventData.Protocol = [string]$Event.Properties[5].Value }
                        } else {
                            $eventData.InternalIP = $p2.Trim()
                            if (-not [string]::IsNullOrWhiteSpace($p3)) { $eventData.Protocol = $p3.Trim() }
                            if ($Event.Properties.Count -gt 4) { $eventData.ErrorCode = [string]$Event.Properties[4].Value }
                        }
                    }
                }
            }
        } elseif ($Event.Id -eq 302 -and $eventData.ErrorCode -eq 'N/A') {
            $eventData.ErrorCode = "0"
        }

        if ($Event.Id -eq 303 -and ($eventData.ErrorCode -eq 'N/A' -or [string]::IsNullOrWhiteSpace($eventData.ErrorCode)) -and $Event.Properties.Count -gt 4) {
            $eventData.ErrorCode = [string]$Event.Properties[4].Value
        }

        if (($eventData.InternalIP -eq 'N/A' -or [string]::IsNullOrWhiteSpace($eventData.InternalIP)) -and
            (Test-RdpMonitorStringLooksLikeIPv4 $eventData.Protocol)) {
            $eventData.InternalIP = $eventData.Protocol.Trim()
            $eventData.Protocol = 'N/A'
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

    $hUser = (ConvertTo-TelegramHtml $Username)
    $hExt = (ConvertTo-TelegramHtml $ExternalIP)
    $hInt = (ConvertTo-TelegramHtml $InternalIP)
    $hProto = (ConvertTo-TelegramHtml $Protocol)
    $hTime = (ConvertTo-TelegramHtml ($TimeCreated.ToString('dd.MM.yyyy HH:mm:ss')))

    $message = "<b>"
    if ($EventID -eq 302) { $message += "🖥️ ПОДКЛЮЧЕНИЕ ЧЕРЕЗ RD GATEWAY" }
    elseif ($EventID -eq 303) {
        if ($ErrorCode -ne "0" -and $ErrorCode -ne "N/A" -and -not [string]::IsNullOrWhiteSpace($ErrorCode)) {
            $message += "⚠️ СЕАНС ЧЕРЕЗ RD GATEWAY ЗАВЕРШЁН С ОШИБКОЙ"
        } else {
            $message += "ℹ️ СЕАНС ЧЕРЕЗ RD GATEWAY ЗАВЕРШЁН"
        }
    }
    else { $message += "⚠️ СОБЫТИЕ RD GATEWAY" }
    $message += "</b>`r`n"

    $message += "👤 Пользователь: $hUser`r`n"
    $message += "🌐 IP пользователя (внешний): $hExt`r`n"
    $message += "🖥️ IP внутренний: $hInt`r`n"
    $message += "🔌 Протокол: $hProto`r`n"
    if ($EventID -eq 303 -and $ErrorCode -ne "0" -and $ErrorCode -ne "N/A") {
        $message += "⚠️ Код ошибки: $(ConvertTo-TelegramHtml $ErrorCode)`r`n"
    }
    $message += "🕐 Время: $hTime`r`n"
    $message += "🔢 Event ID: $EventID"
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
        # PS 5.1: без @() один логин даёт скаляр String (нет .Count); пустой список даёт $null.
        $uniqueUsers = @($usernames | Sort-Object -Unique)
        $message = "<b>📊 ЕЖЕДНЕВНЫЙ ОТЧЕТ</b>`r`n"
        $message += "🖥️ Сервер: $(ConvertTo-TelegramHtml $env:COMPUTERNAME)`r`n"
        $message += "🕐 Время отчета: $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss')`r`n"
        $message += "👥 Активных сессий (quser): $count`r`n"
        if ($uniqueUsers.Count -gt 0) {
            $message += "`r`n<b>Уникальные логины ($($uniqueUsers.Count)):</b>`r`n"
            foreach ($name in $uniqueUsers) {
                $safe = [System.Net.WebUtility]::HtmlEncode($name)
                $message += "  • $safe`r`n"
            }
        } else {
            $message += "`r`n<i>Список пользователей недоступен (quser пуст или недостаточно прав).</i>"
        }
        Send-TelegramMessage -Message $message | Out-Null
        Write-TextFileUtf8Bom -Path $LastReportFile -Text ((Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))
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

    $osKind = Get-OsInstallKind
    $script:IsWorkstation = $osKind.IsWorkstation
    $script:OsInstallKindLabel = $osKind.Label
    Write-Log "Тип ОС (Win32_ProductType=$($osKind.ProductType)): $($osKind.Label)"

    Write-Log "========================================"
    Write-Log "Запуск мониторинга логинов"
    if ($osKind.IsWorkstation) {
        Write-Log "Режим рабочей станции: Security — только LogonType 10 (RDP); при наличии журнала — событие 1149 (Remote Connection Manager)."
    } else {
        Write-Log "Режим сервера: Security — LogonType 2, 3, 10"
    }
    Write-Log "========================================"

    Cleanup-OldLogs
    Send-Heartbeat -IsStartup
    Enable-SecurityAudit

    $rdGatewayAvailable = $false
    if ($EnableRDGatewayMonitoring) { $rdGatewayAvailable = Test-RDGatewayLog }

    $rcmMonitoringEnabled = ($osKind.IsWorkstation -and (Test-RcmLogAvailable))
    if ($osKind.IsWorkstation -and -not $rcmMonitoringEnabled) {
        Write-Log "Рабочая станция: журнал Remote Connection Manager недоступен — уведомления только по Security 4624/4625 (LogonType 10). Проверьте, что включён удалённый рабочий стол."
    }

    $nextHeartbeatTime = (Get-Date).AddSeconds($HeartbeatInterval)
    $nextRotationCheck = Check-AndRotateLog
    $nextReportCheck = Check-AndSendDailyReport
    $lastCheckTime = (Get-Date).AddSeconds(-10)
    $lastGatewayCheckTime = (Get-Date).AddSeconds(-10)
    $lastRcmCheckTime = (Get-Date).AddSeconds(-10)
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
                            if ($osKind.IsWorkstation) {
                                $interactiveTypes = @(10)
                            } else {
                                $interactiveTypes = @(2, 3, 10)
                            }
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

            if ($rcmMonitoringEnabled) {
                $rcmEvents = Get-WinEvent -FilterHashtable @{
                    LogName = $RcmLogName
                    ID = $RcmEventId
                    StartTime = $lastRcmCheckTime
                } -ErrorAction SilentlyContinue

                if ($rcmEvents) {
                    foreach ($event in $rcmEvents) {
                        if ($event.TimeCreated -le $lastRcmCheckTime) { continue }
                        $rcmInfo = Get-Rcm1149EventInfo -Event $event
                        if ($rcmInfo.Username -like "*$") { continue }
                        if (Should-IgnoreEvent -Username $rcmInfo.Username -ProcessName "-" `
                                -ComputerName "-" -EventID 1149 -LogonType 10 -SourceIP $rcmInfo.ClientIP) { continue }

                        $msg = Format-Rcm1149Event -Username $rcmInfo.Username -ClientIP $rcmInfo.ClientIP `
                            -TimeCreated $rcmInfo.TimeCreated -SecurityLogComputerName $event.MachineName
                        Write-Log "Notify RCM 1149: User=$($rcmInfo.Username) IP=$($rcmInfo.ClientIP)"
                        Send-TelegramMessage -Message $msg | Out-Null
                    }
                    $lastRcmCheckTime = ($rcmEvents | Measure-Object -Property TimeCreated -Maximum | Select-Object -ExpandProperty Maximum).AddSeconds(1)
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
            if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) { throw }
            Write-Log "Ошибка цикла мониторинга: $($_.Exception.Message)"
        }
        Start-Sleep -Seconds $MonitorInterval
    }
}

$script:StopNotificationSent = $false
try {
    Test-TelegramConnection | Out-Null
    Start-LoginMonitor -MonitorInterval 5 -MonitorInteractiveOnly
} catch {
    if ($_.Exception -is [System.Management.Automation.PipelineStoppedException]) {
        Write-Log "Выполнение прервано (Ctrl+C / Stop-Pipeline)."
        $script:StopNotificationSent = $true
    } else {
        Write-Log "Критическая ошибка: $($_.Exception.Message)"
        Send-StopNotification -Reason "Критическая ошибка: $($_.Exception.Message)"
        $script:StopNotificationSent = $true
        throw
    }
} finally {
    Release-RdpMonitorSingletonLock
    if (-not $script:StopNotificationSent) {
        Send-StopNotification -Reason "Скрипт завершил работу"
    }
}

