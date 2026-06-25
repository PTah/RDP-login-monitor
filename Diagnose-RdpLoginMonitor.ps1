<#
.SYNOPSIS
    Диагностика RDP Login Monitor после входа по RDP (или при «тишине» в Telegram/SAC).
.DESCRIPTION
    Собирает: процесс монитора, задачи планировщика, настройки (без секретов), хвост login_monitor.log,
    Security 4624/4625/4778/4634, симуляцию фильтров монитора, SAC spool, сессии RDP.
    Отчёт: C:\ProgramData\RDP-login-monitor\Logs\diagnose_YYYYMMDD_HHmmss.txt
.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File Diagnose-RdpLoginMonitor.ps1 -MinutesBack 15 -ExpectedUser jdoe
.NOTES
    Рекомендуется запуск от администратора. Без прав Security-журнал может быть неполным.
#>
[CmdletBinding()]
param(
    [string]$InstallRoot = "$env:ProgramData\RDP-login-monitor",
    [int]$MinutesBack = 15,
    [int]$MonitorLogTailLines = 120,
    [string]$ExpectedUser = '',
    [string]$OutputPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

function Write-Section {
    param([string]$Title)
    $line = ('=' * 72)
    "`n$line`n  $Title`n$line`n"
}

function Redact-SettingsText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '(файл пуст или не прочитан)' }
    $out = $Text
    $out = [regex]::Replace($out, '(?m)^(\s*\$(?:TelegramBotToken|TelegramChatID|SacApiKey|MailSmtpPassword|TelegramBotTokenProtectedB64|TelegramChatIDProtectedB64|MailSmtpPasswordProtectedB64)\s*=).*', '${1}***REDACTED***')
    return $out
}

function Get-EventDataMapFromEvent {
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

function Get-LoginFieldsFromEvent {
    param($Event)
    $map = Get-EventDataMapFromEvent -Event $Event
    $username = $map['TargetUserName']
    if ([string]::IsNullOrWhiteSpace($username)) { $username = $map['AccountName'] }
    if ([string]::IsNullOrWhiteSpace($username)) { $username = $map['UserName'] }
    if ([string]::IsNullOrWhiteSpace($username)) { $username = '-' }

    $computerName = $map['WorkstationName']
    if ([string]::IsNullOrWhiteSpace($computerName)) { $computerName = $map['ComputerName'] }
    if ([string]::IsNullOrWhiteSpace($computerName)) { $computerName = '-' }

    $sourceIP = $map['IpAddress']
    if ([string]::IsNullOrWhiteSpace($sourceIP)) { $sourceIP = $map['SourceNetworkAddress'] }
    if ([string]::IsNullOrWhiteSpace($sourceIP)) { $sourceIP = '-' }

    $logonType = 0
    if ($map.ContainsKey('LogonType') -and $map['LogonType'] -match '(\d+)') {
        $logonType = [int]$Matches[1]
    }

    $processName = $map['LogonProcessName']
    if ([string]::IsNullOrWhiteSpace($processName)) { $processName = $map['AuthenticationPackageName'] }
    if ([string]::IsNullOrWhiteSpace($processName)) { $processName = '-' }

    [pscustomobject]@{
        TimeCreated  = $Event.TimeCreated
        EventId      = [int]$Event.Id
        Username     = $username.Trim()
        ComputerName = $computerName.Trim()
        SourceIP     = $sourceIP.Trim()
        LogonType    = $logonType
        ProcessName  = $processName.Trim()
    }
}

function Test-IsWorkstationOs {
    try {
        $pt = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).ProductType
        return ($pt -eq 1)
    } catch {
        return $false
    }
}

function Get-MonitorVerdictFor4624 {
    param(
        $Fields,
        [bool]$IsWorkstation
    )

    $reasons = [System.Collections.Generic.List[string]]::new()

    if ($Fields.EventId -ne 4624) {
        return [pscustomobject]@{ Verdict = 'N/A'; Reasons = @('не 4624') }
    }

    if ($IsWorkstation) {
        $allowed = @(10)
        $modeLabel = 'workstation LT10'
    } else {
        $allowed = @(2, 3, 10)
        $modeLabel = 'server LT2/3/10'
    }

    if ($allowed -notcontains $Fields.LogonType) {
        $reasons.Add("LogonType $($Fields.LogonType) not in $modeLabel")
    }

    $u = $Fields.Username
    if ([string]::IsNullOrWhiteSpace($u) -or $u -eq '-') { $reasons.Add('пустой Username') }
    if ($u -match '(?i)(\\)?DWM-\d+') { $reasons.Add('DWM-*') }
    if ($u -match '(?i)(\\)?UMFD-\d+') { $reasons.Add('UMFD-*') }
    if ($u -like '*$') { $reasons.Add('machine account ($)') }
    if ($u -match '(?i)^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|ANONYMOUS LOGON)$') { $reasons.Add('служебная учётная запись') }

    if ($Fields.SourceIP -eq '127.0.0.1' -or $Fields.SourceIP -like 'fe80:*' -or $Fields.SourceIP -eq '::1') {
        $reasons.Add("локальный IP ($($Fields.SourceIP))")
    }
    if ($Fields.ComputerName -eq '-' -or $Fields.ComputerName -eq 'N/A') {
        $reasons.Add('WorkstationName = - (встроенный фильтр монитора)')
    }

    if ($Fields.ProcessName -like '*NtLmSsp*') { $reasons.Add('Process NtLmSsp') }

    if ($reasons.Count -eq 0) {
        return [pscustomobject]@{ Verdict = 'WOULD_NOTIFY'; Reasons = @('проходит фильтры монитора (4624)') }
    }
    return [pscustomobject]@{ Verdict = 'WOULD_SKIP'; Reasons = $reasons }
}

function Get-ExternalCommandOutput {
    param(
        [string]$Label,
        [scriptblock]$Block
    )
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("--- $Label ---")
    try {
        $out = & $Block 2>&1
        if ($null -eq $out) {
            [void]$sb.AppendLine('(нет вывода)')
        } else {
            foreach ($line in @($out)) {
                [void]$sb.AppendLine([string]$line)
            }
        }
    } catch {
        [void]$sb.AppendLine("ERROR: $($_.Exception.Message)")
    }
    return $sb.ToString()
}

$startedAt = Get-Date
$isAdmin = $false
try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    $isAdmin = $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }

if (-not $OutputPath) {
    $logDir = Join-Path $InstallRoot 'Logs'
    if (-not (Test-Path -LiteralPath $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    $OutputPath = Join-Path $logDir ("diagnose_{0:yyyyMMdd_HHmmss}.txt" -f $startedAt)
}

$report = New-Object System.Text.StringBuilder
[void]$report.AppendLine('RDP Login Monitor — диагностический отчёт')
[void]$report.AppendLine("Сформирован: $($startedAt.ToString('yyyy-MM-dd HH:mm:ss'))")
[void]$report.AppendLine("Компьютер: $env:COMPUTERNAME")
[void]$report.AppendLine("Пользователь сеанса: $([Environment]::UserDomainName)\$([Environment]::UserName)")
[void]$report.AppendLine("Elevated (Admin): $isAdmin")
[void]$report.AppendLine("InstallRoot: $InstallRoot")
[void]$report.AppendLine("MinutesBack: $MinutesBack")
if ($ExpectedUser) { [void]$report.AppendLine("ExpectedUser: $ExpectedUser") }
[void]$report.AppendLine("ReportPath: $OutputPath")

[void]$report.Append((Write-Section '1. Процесс Login_Monitor.ps1'))
$procs = @(
    Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -match 'Login_Monitor\.ps1' }
)
if ($procs.Count -eq 0) {
    [void]$report.AppendLine('НЕ НАЙДЕН процесс Login_Monitor.ps1')
} else {
    foreach ($proc in $procs) {
        [void]$report.AppendLine("PID=$($proc.ProcessId) Start=$($proc.CreationDate)")
        [void]$report.AppendLine("  $($proc.CommandLine)")
    }
}

[void]$report.Append((Write-Section '2. Scheduled Tasks'))
foreach ($tn in @('RDP-Login-Monitor', 'RDP-Login-Monitor-Watchdog')) {
    [void]$report.AppendLine("--- $tn ---")
    $q = schtasks.exe /Query /TN $tn /FO LIST /V 2>&1
    if ($LASTEXITCODE -ne 0) {
        [void]$report.AppendLine('  (задача не найдена или ошибка запроса)')
    } else {
        foreach ($line in @($q)) { [void]$report.AppendLine("  $line") }
    }
}

[void]$report.Append((Write-Section '3. Версии / deploy markers'))
foreach ($rel in @('version.txt', 'deployed_version.txt', 'deploy_last_update.txt', 'restart.request')) {
    $fp = Join-Path $InstallRoot $rel
    [void]$report.AppendLine("--- $rel ---")
    if (Test-Path -LiteralPath $fp) {
        Get-Content -LiteralPath $fp -ErrorAction SilentlyContinue | ForEach-Object {
            [void]$report.AppendLine("  $_")
        }
    } else {
        [void]$report.AppendLine('  (нет файла)')
    }
}

$lmPath = Join-Path $InstallRoot 'Login_Monitor.ps1'
if (Test-Path -LiteralPath $lmPath) {
    $verLine = Select-String -LiteralPath $lmPath -Pattern '^\$ScriptVersion\s*=' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($verLine) {
        [void]$report.AppendLine("Login_Monitor.ps1: $($verLine.Line.Trim())")
    }
}

[void]$report.Append((Write-Section '4. login_monitor.settings.ps1 (redacted)'))
$settingsPath = Join-Path $InstallRoot 'login_monitor.settings.ps1'
if (Test-Path -LiteralPath $settingsPath) {
    $raw = Get-Content -LiteralPath $settingsPath -Raw -ErrorAction SilentlyContinue
    [void]$report.AppendLine(Redact-SettingsText -Text $raw)
} else {
    [void]$report.AppendLine('Файл settings не найден')
}

[void]$report.AppendLine('')
[void]$report.AppendLine('--- ignore.lst ---')
$ignorePath = Join-Path $InstallRoot 'ignore.lst'
if (Test-Path -LiteralPath $ignorePath) {
    Get-Content -LiteralPath $ignorePath | ForEach-Object { [void]$report.AppendLine("  $_") }
} else {
    [void]$report.AppendLine('  (нет файла)')
}

[void]$report.Append((Write-Section '5. SAC spool / heartbeat'))
$spoolDir = Join-Path $InstallRoot 'sac-spool'
if (Test-Path -LiteralPath $spoolDir) {
    $spoolFiles = @(Get-ChildItem -LiteralPath $spoolDir -Filter '*.json' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
    [void]$report.AppendLine("sac-spool: файлов $($spoolFiles.Count)")
    $spoolFiles | Select-Object -First 5 | ForEach-Object {
        [void]$report.AppendLine("  $($_.Name)  $($_.LastWriteTime)")
    }
} else {
    [void]$report.AppendLine('sac-spool: каталог отсутствует')
}
$hbPath = Join-Path $InstallRoot 'heartbeat.txt'
if (Test-Path -LiteralPath $hbPath) {
    [void]$report.AppendLine("heartbeat.txt: $(Get-Content -LiteralPath $hbPath -First 1)")
} else {
    [void]$report.AppendLine('heartbeat.txt: нет')
}

[void]$report.Append((Write-Section "6. login_monitor.log (last $MonitorLogTailLines lines)"))
$monLog = Join-Path $InstallRoot 'Logs\login_monitor.log'
if (Test-Path -LiteralPath $monLog) {
    Get-Content -LiteralPath $monLog -Tail $MonitorLogTailLines -ErrorAction SilentlyContinue | ForEach-Object {
        [void]$report.AppendLine($_)
    }
} else {
    [void]$report.AppendLine('login_monitor.log не найден')
}

[void]$report.AppendLine('')
[void]$report.AppendLine('--- login_monitor.log: Notify / Skip / dedup / rdp.login (last 50 matches) ---')
if (Test-Path -LiteralPath $monLog) {
    Select-String -LiteralPath $monLog -Pattern 'Notify:|Skip 4624|Notify dedup|SAC: accepted.*rdp\.login|type=rdp\.login' -ErrorAction SilentlyContinue |
        Select-Object -Last 50 |
        ForEach-Object { [void]$report.AppendLine($_.Line) }
}

[void]$report.Append((Write-Section '7. RDP / interactive sessions'))
[void]$report.AppendLine((Get-ExternalCommandOutput -Label 'quser' -Block { quser.exe 2>&1 }))
[void]$report.AppendLine((Get-ExternalCommandOutput -Label 'query session' -Block { query.exe session 2>&1 }))

[void]$report.Append((Write-Section "8. Security log (last $MinutesBack min)"))
if (-not $isAdmin) {
    [void]$report.AppendLine('WARN: скрипт не от администратора — чтение Security может быть неполным.')
}

$since = (Get-Date).AddMinutes(-1 * [math]::Abs($MinutesBack))
$RcmLogName = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
$isWs = Test-IsWorkstationOs
[void]$report.AppendLine("OS ProductType workstation=$isWs (server mode LT 2/3/10, workstation LT 10)")
[void]$report.AppendLine("Window StartTime >= $($since.ToString('yyyy-MM-dd HH:mm:ss'))")
[void]$report.AppendLine('')

foreach ($eid in @(4624, 4625, 4778, 4634)) {
    [void]$report.AppendLine("--- Event ID $eid ---")
    try {
        $evs = @(Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            ID        = $eid
            StartTime = $since
        } -ErrorAction Stop | Sort-Object TimeCreated)
    } catch {
        [void]$report.AppendLine("  (нет событий или ошибка: $($_.Exception.Message))")
        continue
    }

    if ($evs.Count -eq 0) {
        [void]$report.AppendLine('  (нет событий в окне)')
        continue
    }

    foreach ($ev in $evs) {
        if ($eid -eq 4624 -or $eid -eq 4625) {
            $f = Get-LoginFieldsFromEvent -Event $ev
            $verdict = if ($eid -eq 4624) { Get-MonitorVerdictFor4624 -Fields $f -IsWorkstation $isWs } else { $null }

            $marker = ''
            if ($ExpectedUser -and $f.Username -like "*$ExpectedUser*") { $marker = ' <<<< EXPECTED USER' }

            [void]$report.AppendLine(
                ("  {0:yyyy-MM-dd HH:mm:ss} ID={1} User={2} LT={3} IP={4} Wks={5} Proc={6}{7}" -f
                    $f.TimeCreated, $f.EventId, $f.Username, $f.LogonType, $f.SourceIP, $f.ComputerName, $f.ProcessName, $marker)
            )
            if ($verdict) {
                [void]$report.AppendLine("    MONITOR: $($verdict.Verdict) — $($verdict.Reasons -join '; ')")
            }
        } else {
            [void]$report.AppendLine("  $($ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))  RecordId=$($ev.RecordId)")
            $f = Get-LoginFieldsFromEvent -Event $ev
            if ($f.Username -ne '-') {
                [void]$report.AppendLine("    User=$($f.Username) LT=$($f.LogonType) IP=$($f.SourceIP)")
            }
        }
    }
}

[void]$report.Append((Write-Section '9. Краткий итог'))
$recent4624 = @()
try {
    $recent4624 = @(Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        ID        = 4624
        StartTime = $since
    } -ErrorAction SilentlyContinue)
} catch { }

$notifyable = @()
foreach ($ev in $recent4624) {
    $f = Get-LoginFieldsFromEvent -Event $ev
    $v = Get-MonitorVerdictFor4624 -Fields $f -IsWorkstation $isWs
    if ($v.Verdict -eq 'WOULD_NOTIFY') { $notifyable += $f }
}

[void]$report.AppendLine("Security 4624 в окне: $($recent4624.Count)")
[void]$report.AppendLine("Из них базовые фильтры монитора пропустили бы: $($notifyable.Count)")

try {
    $reconnectCount = @(Get-WinEvent -FilterHashtable @{
        LogName = 'Security'; ID = 4778; StartTime = $since
    } -ErrorAction SilentlyContinue).Count
    [void]$report.AppendLine("Security 4778 (reconnect): $reconnectCount")
} catch {
    [void]$report.AppendLine('Security 4778 (reconnect): n/a')
}

$sacLoginLines = @()
if (Test-Path -LiteralPath $monLog) {
    $sinceLog = $since.ToString('yyyy-MM-dd HH:mm')
    $sacLoginLines = @(Select-String -LiteralPath $monLog -Pattern 'SAC: accepted.*type=rdp\.login\.success' -ErrorAction SilentlyContinue |
        Where-Object { $_.Line -ge $sinceLog } |
        Select-Object -ExpandProperty Line)
}
[void]$report.AppendLine("SAC ingest rdp.login.success в login_monitor.log (после $sinceLog): $($sacLoginLines.Count)")
foreach ($ln in $sacLoginLines) { [void]$report.AppendLine("  $ln") }

if ($notifyable.Count -eq 0 -and $recent4624.Count -gt 0) {
    [void]$report.AppendLine('')
    [void]$report.AppendLine('Все 4624 в окне отфильтрованы базовыми правилами — см. MONITOR: WOULD_SKIP выше.')
    [void]$report.AppendLine('Дополнительно: ignore.lst, IgnoreAdvapiNetworkLogonSourceIps в settings, dedup 90s.')
} elseif ($recent4624.Count -eq 0) {
    [void]$report.AppendLine('')
    [void]$report.AppendLine('Нет 4624 в окне — возможен reconnect (4778) без нового 4624.')
    [void]$report.AppendLine('Повторите: Sign out → новый RDP → скрипт с -MinutesBack 5.')
}

[void]$report.AppendLine('')
[void]$report.AppendLine('UseSAC=exclusive: Telegram по rdp.login.success только из SAC (не локально агентом).')
[void]$report.AppendLine('На сервере RDS без аудита Security 4624 — смотрите RCM Operational 1149 (2.1.5-SAC+: исправлен silent skip при ComputerName=-).')
[void]$report.AppendLine('rdp.login.success = severity info; при SAC min_severity=warning Telegram не уйдёт, но событие в UI SAC должно быть.')

[void]$report.Append((Write-Section '10. RCM Operational 1149'))
$recent1149 = @()
try {
    $recent1149 = @(Get-WinEvent -FilterHashtable @{
        LogName   = $RcmLogName
        ID        = 1149
        StartTime = $since
    } -ErrorAction SilentlyContinue)
} catch { }
[void]$report.AppendLine("RCM 1149 в окне ($RcmLogName): $($recent1149.Count)")
foreach ($ev in $recent1149 | Select-Object -First 8) {
    $u = '-'; $ip = '-'
    try {
        if ($ev.Properties.Count -gt 0) { $u = [string]$ev.Properties[0].Value }
        if ($ev.Properties.Count -gt 2) { $ip = [string]$ev.Properties[2].Value }
    } catch { }
    [void]$report.AppendLine("  $($ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) User=$u IP=$ip")
}
$rcmNotifyLines = @()
if (Test-Path -LiteralPath $monLog) {
    $sinceLog = $since.ToString('yyyy-MM-dd HH:mm')
    $rcmNotifyLines = @(Select-String -LiteralPath $monLog -Pattern 'Notify RCM 1149|Skip 1149' -ErrorAction SilentlyContinue |
        Where-Object { $_.Line -ge $sinceLog } |
        Select-Object -ExpandProperty Line)
}
[void]$report.AppendLine("Строки Notify/Skip 1149 в login_monitor.log: $($rcmNotifyLines.Count)")
foreach ($ln in $rcmNotifyLines | Select-Object -Last 10) { [void]$report.AppendLine("  $ln") }
if ($recent1149.Count -gt 0 -and $rcmNotifyLines.Count -eq 0) {
    [void]$report.AppendLine('ВНИМАНИЕ: 1149 в журнале есть, в логе агента нет Notify/Skip — вероятен баг 2.1.4 (все 1149 отбрасывались) или агент не работал в момент входа.')
}

[void]$report.AppendLine('')
[void]$report.AppendLine('Проверьте SAC: type=rdp.login.success, hostname, время входа, event_id из login_monitor.log.')

$text = $report.ToString()
[System.IO.File]::WriteAllText($OutputPath, $text, (New-Object System.Text.UTF8Encoding $true))

Write-Host ''
Write-Host "Отчёт сохранён: $OutputPath" -ForegroundColor Green
Write-Host 'Пришлите этот файл для анализа.' -ForegroundColor Cyan
Write-Host ''
Get-Content -LiteralPath $OutputPath -Tail 25
