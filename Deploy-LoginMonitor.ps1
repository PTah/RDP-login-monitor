<#
.SYNOPSIS
    Доставка Login_Monitor.ps1 с файловой шары по версии (домен: ПК и серверы).
.DESCRIPTION
    Читает version.txt на шаре, сравнивает с локальной меткой (или с версией в установленном скрипте).
    При необходимости копирует Login_Monitor.ps1 в C:\ProgramData\RDP-login-monitor\, регистрирует задачи (-InstallTasks),
    перезапускает процесс монитора.
    Предназначен для GPO «Сценарий запуска компьютера» (SYSTEM); можно запускать вручную от администратора.

    СТРУКТУРА НА ШАРЕ (пример):
      \\dc\share\RDP-login-monitor\Login_Monitor.ps1
      \\dc\share\RDP-login-monitor\Sac-Client.ps1   — обязателен для SAC
      \\dc\share\RDP-login-monitor\login_monitor.settings.example.ps1
      \\dc\share\RDP-login-monitor\version.txt         — одна строка, например: 1.3.0
      \\dc\share\RDP-login-monitor\Deploy-LoginMonitor.ps1

    Если Deploy-LoginMonitor.ps1 запускают с этой шары, параметр -SourceShareRoot можно не указывать —
    корень шары берётся из расположения этого файла.

.NOTES
    Лог: C:\ProgramData\RDP-login-monitor\Logs\deploy.log

    Сравнение версий: метки вида 1.2.27-SAC сравниваются по полному тексту (без учёта регистра);
    для upgrade/downgrade используется числовой префикс (1.2.27). См. Docs/deploy-rdp-login-monitor.md.
#>

[CmdletBinding()]
param(
    # UNC-каталог, где лежат Login_Monitor.ps1 и version.txt. Пусто = родительский каталог этого скрипта.
    [string]$SourceShareRoot = "",
    [switch]$WhatIf,
    # После обновления не стартовать монитор (только файлы и задачи).
    [switch]$SkipStartMonitorAfterUpdate,
    # Разрешить установку более старой версии с шары (по умолчанию откаты блокируются).
    [switch]$AllowDowngrade
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-DeployRunningElevated {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        # LocalSystem (GPO startup / задачи SYSTEM): не всегда даёт true на BuiltInRole::Administrator.
        if ($null -ne $id.User -and $id.User.Value -eq 'S-1-5-18') { return $true }
        $p = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

$InstallRoot = [System.IO.Path]::GetFullPath("$env:ProgramData\RDP-login-monitor")
$LocalScript = Join-Path $InstallRoot "Login_Monitor.ps1"
$VersionStampPath = Join-Path $InstallRoot "deployed_version.txt"
$DeployUpdateMarkerPath = Join-Path $InstallRoot "deploy_last_update.txt"
$DeployLogPath = Join-Path $InstallRoot "Logs\deploy.log"
$ScriptName = "Login_Monitor.ps1"
$SacClientName = "Sac-Client.ps1"
$VersionFileName = "version.txt"
$DeployBundleFiles = @($ScriptName, $SacClientName, 'Diagnose-RdpLoginMonitor.ps1', 'RdpMonitor-TaskQuery.ps1')
$PsExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

$Utf8Bom = New-Object System.Text.UTF8Encoding $true

function Write-DeployLog {
    param([string]$Message)
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message" + [Environment]::NewLine
    try {
        $dir = Split-Path $DeployLogPath -Parent
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        [System.IO.File]::AppendAllText($DeployLogPath, $line, $Utf8Bom)
    } catch { }
    if ($Host.Name -eq 'ConsoleHost' -or $Host.Name -eq 'Windows PowerShell ISE Host') {
        Write-Host $line.TrimEnd("`r`n")
    }
}

function Resolve-SourceShareRoot {
    if (-not [string]::IsNullOrWhiteSpace($SourceShareRoot)) {
        return [System.IO.Path]::GetFullPath($SourceShareRoot.TrimEnd('\'))
    }
    $here = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($here)) { $here = $MyInvocation.MyCommand.Path }
    if ([string]::IsNullOrWhiteSpace($here)) {
        throw "Укажите -SourceShareRoot или запускайте Deploy-LoginMonitor.ps1 с путём к файлу (например с UNC-шары)."
    }
    return [System.IO.Path]::GetFullPath((Split-Path -Parent $here))
}

function Read-VersionLineFromFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $raw = (Get-Content -LiteralPath $Path -TotalCount 3 -ErrorAction Stop | Where-Object { $_ -match '\S' }) | Select-Object -First 1
    if ($null -eq $raw) { return $null }
    return ([string]$raw).Trim() -replace '^v', ''
}

function Get-LocalDeployedVersion {
    $fromStamp = Read-VersionLineFromFile -Path $VersionStampPath
    if (-not [string]::IsNullOrWhiteSpace($fromStamp)) { return $fromStamp }

    if (-not (Test-Path -LiteralPath $LocalScript)) { return $null }

    try {
        $head = Get-Content -LiteralPath $LocalScript -TotalCount 120 -ErrorAction Stop
        foreach ($ln in $head) {
            if ($ln -match '^\s*\$ScriptVersion\s*=\s*["'']([^"'']+)["'']') {
                return ([string]$Matches[1]).Trim() -replace '^v', ''
            }
        }
    } catch { }

    return $null
}

function Normalize-DeployVersionLabel {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    return ([string]$Text).Trim() -replace '^v', ''
}

function Normalize-VersionOrNull {
    param([string]$Text)
    $t = Normalize-DeployVersionLabel -Text $Text
    if ($null -eq $t) { return $null }
    try {
        return [version]$t
    } catch { }
    if ($t -match '^([0-9]+(?:\.[0-9]+){0,3})') {
        try { return [version]$Matches[1] } catch { }
    }
    return $null
}

function Compare-VersionStrings {
    param([string]$Left, [string]$Right)
    if ([string]::IsNullOrWhiteSpace($Left) -and [string]::IsNullOrWhiteSpace($Right)) { return 0 }
    if ([string]::IsNullOrWhiteSpace($Left)) { return -1 }
    if ([string]::IsNullOrWhiteSpace($Right)) { return 1 }

    $lt = Normalize-DeployVersionLabel -Text $Left
    $rt = Normalize-DeployVersionLabel -Text $Right
    if ($lt.Equals($rt, [StringComparison]::OrdinalIgnoreCase)) { return 0 }

    $a = Normalize-VersionOrNull -Text $Left
    $b = Normalize-VersionOrNull -Text $Right
    if ($null -eq $a -or $null -eq $b) { return $null }
    return $a.CompareTo($b)
}

function Get-ScriptPathFromCommandLine {
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

function Test-CommandLineIsWatchdog {
    param([string]$CommandLine)
    return ($CommandLine -match '(?i)(^|\s)-Watchdog(\s|$)')
}

function Test-RdpMonitorMainProcessRunning {
    param([string]$CanonicalScript)
    try {
        $procs = Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe' OR Name = 'pwsh.exe'" -ErrorAction Stop
        foreach ($proc in $procs) {
            $cl = [string]$proc.CommandLine
            if ($cl -notmatch 'Login_Monitor\.ps1') { continue }
            if (Test-CommandLineIsWatchdog -CommandLine $cl) { continue }
            $sp = Get-ScriptPathFromCommandLine -CommandLine $cl
            if ($null -eq $sp) { continue }
            if ([System.IO.Path]::GetFullPath($sp) -ne $CanonicalScript) { continue }
            if ([int]$proc.ProcessId -eq $PID) { continue }
            return $true
        }
    } catch { }
    return $false
}

function Set-RdpMonitorRestartRequestFromDeploy {
    param(
        [ValidateSet('settings', 'recycle', 'stop')]
        [string]$Mode = 'stop',
        [string]$Reason = 'deploy'
    )

    if (-not (Test-Path -LiteralPath $InstallRoot)) {
        New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
    }
    $restartFile = Join-Path $InstallRoot 'restart.request'
    $content = @(
        "mode=$Mode"
        "reason=$Reason"
        "requested_at=$((Get-Date).ToString('o'))"
    ) -join "`r`n"
    [System.IO.File]::WriteAllText($restartFile, $content + "`r`n", $Utf8Bom)
}

function Get-RdpMonitorSettingsRaw {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try {
        return Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    } catch {
        return $null
    }
}

function Get-DeployFileSha256 {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
}

function Test-RdpMonitorDeployBundleNeedsSync {
    param([string]$ShareRoot)
    foreach ($rel in $DeployBundleFiles) {
        $src = Join-Path $ShareRoot $rel
        if (-not (Test-Path -LiteralPath $src)) {
            if ($rel -eq $SacClientName) {
                Write-DeployLog "ОШИБКА: на шаре нет обязательного $SacClientName — опубликуйте пакет (update-rdp-monitor.ps1)."
            }
            continue
        }
        $dst = Join-Path $InstallRoot $rel
        if (-not (Test-Path -LiteralPath $dst)) { return $true }
        $hs = Get-DeployFileSha256 -Path $src
        $hd = Get-DeployFileSha256 -Path $dst
        if ($hs -ne $hd) { return $true }
    }
    return $false
}

function Copy-RdpMonitorDeployBundle {
    param([string]$ShareRoot)
    foreach ($rel in $DeployBundleFiles) {
        $src = Join-Path $ShareRoot $rel
        $dst = Join-Path $InstallRoot $rel
        if (-not (Test-Path -LiteralPath $src)) {
            if ($rel -eq $SacClientName) {
                Write-DeployLog "Предупреждение: на шаре нет $SacClientName — SAC недоступен до публикации файла на шару."
            } elseif ($rel -eq 'RdpMonitor-TaskQuery.ps1') {
                Write-DeployLog "Предупреждение: на шаре нет RdpMonitor-TaskQuery.ps1 — выполните update-rdp-monitor.ps1 на сервере публикации."
            }
            continue
        }
        Copy-Item -LiteralPath $src -Destination $dst -Force
        Write-DeployLog "Файл скопирован: $dst"
    }
}

function Test-RdpMonitorSettingsNeedsSacBootstrap {
    param([string]$SettingsPath)
    $c = Get-RdpMonitorSettingsRaw -Path $SettingsPath
    if ([string]::IsNullOrWhiteSpace($c)) { return $true }

    if ($c -notmatch '(?m)^\s*\$UseSAC\s*=') { return $true }
    if ($c -match '(?m)^\s*\$UseSAC\s*=\s*[''"]off[''"]') {
        if ($c -notmatch '(?m)^\s*\$SacApiKey\s*=\s*[''"]sac_[^''"]+[''"]') { return $true }
    }
    if ($c -match '(?m)^\s*\$SacApiKey\s*=\s*[''"]\s*[''"]') { return $true }
    if ($c -notmatch '(?m)^\s*\$SacApiKey\s*=\s*[''"]sac_[^''"]+[''"]') { return $true }
    if ($c -notmatch '(?m)^\s*\$SacUrl\s*=\s*[''"]https?://[^''"]+[''"]') { return $true }

    return $false
}

function Test-RdpMonitorSettingsNeedsServerDisplayNameHint {
    param([string]$SettingsPath)
    if (-not (Test-Path -LiteralPath $SettingsPath)) { return $false }
    $c = Get-RdpMonitorSettingsRaw -Path $SettingsPath
    if ([string]::IsNullOrWhiteSpace($c)) { return $false }
    if ($c -match '(?m)^\s*(\#\s*)?\$ServerDisplayName\s*=') { return $false }
    return $true
}

function Test-RdpMonitorSettingsNeedsDailyReportHint {
    param([string]$SettingsPath)
    if (-not (Test-Path -LiteralPath $SettingsPath)) { return $false }
    $c = Get-RdpMonitorSettingsRaw -Path $SettingsPath
    if ([string]::IsNullOrWhiteSpace($c)) { return $false }
    if ($c -match '(?m)^\s*(\#\s*)?\$DailyReportEnabled\s*=') { return $false }
    return $true
}

function Test-RdpMonitorSettingsHasInvalidDailyReportAssignment {
    param([string]$SettingsPath)
    if (-not (Test-Path -LiteralPath $SettingsPath)) { return $false }
    $c = Get-RdpMonitorSettingsRaw -Path $SettingsPath
    if ([string]::IsNullOrWhiteSpace($c)) { return $false }
    if ($c -match '(?m)^\s*\$DailyReportEnabled\s*=\s*\$(?:true|false)\b') { return $false }
    if ($c -match '(?m)^\s*\$DailyReportEnabled\s*=\s*(?:0|1)\s*(?:#.*)?$') { return $false }
    if ($c -match '(?m)^\s*\$DailyReportEnabled\s*=\s*(?:true|false)\s*(?:#.*)?$') { return $true }
    return $false
}

function Repair-RdpMonitorSettingsDailyReportAssignmentIfInvalid {
    param([string]$LocalSettings)
    if (-not (Test-Path -LiteralPath $LocalSettings)) { return $false }
    if (-not (Test-RdpMonitorSettingsHasInvalidDailyReportAssignment -SettingsPath $LocalSettings)) {
        return $false
    }

    $c = Get-RdpMonitorSettingsRaw -Path $LocalSettings
    $newContent = [regex]::Replace(
        $c,
        '(?m)^(\s*\$DailyReportEnabled\s*=\s*)(true|false)(\s*(?:#.*)?)$',
        { param($m) "$($m.Groups[1].Value)`$$($m.Groups[2].Value)$($m.Groups[3].Value)" }
    )
    if ($newContent -eq $c) { return $false }

    $bak = "$LocalSettings.bak.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Copy-Item -LiteralPath $LocalSettings -Destination $bak -Force
    [System.IO.File]::WriteAllText($LocalSettings, $newContent.TrimEnd() + "`r`n", $Utf8Bom)
    Write-DeployLog "login_monitor.settings.ps1: исправлено DailyReportEnabled = true/false без dollar — заменено на `$true/`$false (резервная копия: $bak)"
    return $true
}

function Update-RdpMonitorSettingsDailyReportHintIfMissing {
    param([string]$LocalSettings)
    if (-not (Test-Path -LiteralPath $LocalSettings)) { return $false }
    if (-not (Test-RdpMonitorSettingsNeedsDailyReportHint -SettingsPath $LocalSettings)) {
        return $false
    }

    $c = Get-RdpMonitorSettingsRaw -Path $LocalSettings
    if ([string]::IsNullOrWhiteSpace($c)) { return $false }

    $hintBlock = @(
        '# --- Суточный отчёт report.daily.rdp (агент или только SAC) ---'
        '# $DailyReportEnabled = $false   # по умолчанию: только SAC; $true или 1 — отчёт с агента'
        '# Не пишите "= false" без $ — PowerShell воспримет false как команду.'
    ) -join "`r`n"

    $bak = "$LocalSettings.bak.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Copy-Item -LiteralPath $LocalSettings -Destination $bak -Force
    Write-DeployLog "Добавление закомментированного `$DailyReportEnabled в login_monitor.settings.ps1; резервная копия: $bak"

    $insertBefore = '(?m)^\s*#\s*---\s*Security Alert Center'
    if ($c -match $insertBefore) {
        $newContent = [regex]::Replace($c, $insertBefore, ($hintBlock + "`r`n`r`n" + '$0'), 1)
    } else {
        $newContent = ($c.TrimEnd() + "`r`n`r`n" + $hintBlock + "`r`n")
    }
    [System.IO.File]::WriteAllText($LocalSettings, $newContent.TrimEnd() + "`r`n", $Utf8Bom)
    Write-DeployLog 'login_monitor.settings.ps1: добавлена подсказка # $DailyReportEnabled = $false'
    return $true
}

function Sync-RdpMonitorSettingsDailyReportPatches {
    param([string]$LocalSettings)
    if (-not (Test-Path -LiteralPath $LocalSettings)) { return $false }
    $changed = $false
    if (Repair-RdpMonitorSettingsDailyReportAssignmentIfInvalid -LocalSettings $LocalSettings) {
        $changed = $true
    }
    if (Update-RdpMonitorSettingsDailyReportHintIfMissing -LocalSettings $LocalSettings) {
        $changed = $true
    }
    return $changed
}

function Test-RdpMonitorExchangeServerRole {
    if (-not [string]::IsNullOrWhiteSpace($env:ExchangeInstallPath)) {
        if (Test-Path -LiteralPath $env:ExchangeInstallPath) { return $true }
    }
    foreach ($regPath in @(
        'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup',
        'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v14\Setup'
    )) {
        try {
            if ($null -ne (Get-ItemProperty -LiteralPath $regPath -ErrorAction Stop)) { return $true }
        } catch { }
    }
    foreach ($root in @(
        'C:\Program Files\Microsoft\Exchange Server\V15',
        'C:\Program Files\Microsoft\Exchange Server\V14'
    )) {
        if (Test-Path -LiteralPath (Join-Path $root 'bin\RemoteExchange.ps1')) { return $true }
    }
    try {
        $svc = Get-Service -Name 'MSExchangeIS', 'MSExchangeTransport' -ErrorAction SilentlyContinue |
            Where-Object { $_.Status -eq 'Running' } |
            Select-Object -First 1
        if ($null -ne $svc) { return $true }
    } catch { }
    return $false
}

function Get-RdpMonitorExchangeNoiseSettingDefinitions {
    return @(
        @{
            Pattern = '(?m)^\s*(\#\s*)?\$\{Ignore4624-LT3-EmptyIP-Event\}\s*='
            Line    = '${Ignore4624-LT3-EmptyIP-Event} = $true'
        },
        @{
            Pattern = '(?m)^\s*(\#\s*)?\$WinRmIgnoreLocalSource\s*='
            Line    = '$WinRmIgnoreLocalSource = 1'
        },
        @{
            Pattern = '(?m)^\s*(\#\s*)?\$WinRmIgnoreMachineAccounts\s*='
            Line    = '$WinRmIgnoreMachineAccounts = 1'
        },
        @{
            Pattern = '(?m)^\s*(\#\s*)?\$WinRmExchangeStrictMode\s*='
            Line    = '$WinRmExchangeStrictMode = 1'
        }
    )
}

function Test-RdpMonitorSettingsNeedsExchangeNoisePatch {
    param([string]$SettingsPath)
    if (-not (Test-RdpMonitorExchangeServerRole)) { return $false }
    if (-not (Test-Path -LiteralPath $SettingsPath)) { return $false }
    $c = Get-RdpMonitorSettingsRaw -Path $SettingsPath
    if ([string]::IsNullOrWhiteSpace($c)) { return $false }
    foreach ($def in Get-RdpMonitorExchangeNoiseSettingDefinitions) {
        if ($c -notmatch $def.Pattern) { return $true }
    }
    return $false
}

function Sync-RdpMonitorSettingsExchangeNoisePatches {
    param([string]$LocalSettings)
    if (-not (Test-RdpMonitorExchangeServerRole)) { return $false }
    if (-not (Test-Path -LiteralPath $LocalSettings)) { return $false }
    if (-not (Test-RdpMonitorSettingsNeedsExchangeNoisePatch -SettingsPath $LocalSettings)) {
        return $false
    }

    $c = Get-RdpMonitorSettingsRaw -Path $LocalSettings
    $linesToAdd = [System.Collections.Generic.List[string]]::new()
    [void]$linesToAdd.Add('# --- Exchange: подавление шумов WinRM/4624 (добавлено Deploy-LoginMonitor) ---')
    foreach ($def in Get-RdpMonitorExchangeNoiseSettingDefinitions) {
        if ($c -notmatch $def.Pattern) {
            [void]$linesToAdd.Add($def.Line)
        }
    }
    if ($linesToAdd.Count -le 1) { return $false }

    $bak = "$LocalSettings.bak.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Copy-Item -LiteralPath $LocalSettings -Destination $bak -Force
    Write-DeployLog "Добавление Exchange noise settings в login_monitor.settings.ps1; резервная копия: $bak"

    $block = ($linesToAdd -join "`r`n")
    $insertBefore = '(?m)^\s*#\s*---\s*Exchange noise filter'
    if ($c -match $insertBefore) {
        $newContent = [regex]::Replace($c, $insertBefore, ($block + "`r`n`r`n" + '$0'), 1)
    } else {
        $insertLockout = '(?m)^\s*#\s*---\s*Блокировка учётной записи'
        if ($c -match $insertLockout) {
            $newContent = [regex]::Replace($c, $insertLockout, ($block + "`r`n`r`n" + '$0'), 1)
        } else {
            $newContent = ($c.TrimEnd() + "`r`n`r`n" + $block + "`r`n")
        }
    }
    [System.IO.File]::WriteAllText($LocalSettings, $newContent.TrimEnd() + "`r`n", $Utf8Bom)
    Write-DeployLog ("login_monitor.settings.ps1: Exchange noise — добавлено строк: {0}" -f ($linesToAdd.Count - 1))
    return $true
}

function Get-RdpMonitorWinRmInboundSettingDefinitions {
    return @(
        @{
            Pattern = '(?m)^\s*(\#\s*)?\$EnableWinRmInboundMonitoring\s*='
            Line    = '$EnableWinRmInboundMonitoring = 1'
        },
        @{
            Pattern = '(?m)^\s*(\#\s*)?\$WinRmLogName\s*='
            Line    = '$WinRmLogName = ''Microsoft-Windows-WinRM/Operational'''
        },
        @{
            Pattern = '(?m)^\s*(\#\s*)?\$WinRmInboundShellEventIds\s*='
            Line    = '$WinRmInboundShellEventIds = @(91)'
        },
        @{
            Pattern = '(?m)^\s*(\#\s*)?\$WinRmCorrelateSecurity4624\s*='
            Line    = '$WinRmCorrelateSecurity4624 = 1'
        },
        @{
            Pattern = '(?m)^\s*(\#\s*)?\$WinRm4624CorrelationWindowSeconds\s*='
            Line    = '$WinRm4624CorrelationWindowSeconds = 15'
        }
    )
}

function Test-RdpMonitorSettingsNeedsWinRmInboundBlock {
    param([string]$SettingsPath)
    if (-not (Test-Path -LiteralPath $SettingsPath)) { return $false }
    $c = Get-RdpMonitorSettingsRaw -Path $SettingsPath
    if ([string]::IsNullOrWhiteSpace($c)) { return $false }
    foreach ($def in Get-RdpMonitorWinRmInboundSettingDefinitions) {
        if ($c -notmatch $def.Pattern) { return $true }
    }
    return $false
}

function Repair-RdpMonitorSettingsWinRmLinesIfInvalid {
    param([string]$LocalSettings)
    if (-not (Test-Path -LiteralPath $LocalSettings)) { return $false }

    $c = Get-RdpMonitorSettingsRaw -Path $LocalSettings
    if ([string]::IsNullOrWhiteSpace($c)) { return $false }

    $winRmNames = @(
        'EnableWinRmInboundMonitoring',
        'WinRmLogName',
        'WinRmInboundShellEventIds',
        'WinRmCorrelateSecurity4624',
        'WinRm4624CorrelationWindowSeconds',
        'WinRmIgnoreLocalSource',
        'WinRmIgnoreMachineAccounts',
        'WinRmExchangeStrictMode'
    )
    $newContent = $c
    $fixed = $false
    foreach ($name in $winRmNames) {
        $escaped = [regex]::Escape($name)
        $pattern = "(?m)^(\s*)(?<![\$])$escaped(\s*=)"
        if ($newContent -match $pattern) {
            $newContent = [regex]::Replace($newContent, $pattern, ('${1}$' + $name + '${2}'))
            $fixed = $true
        }
    }
    if (-not $fixed) { return $false }

    $bak = "$LocalSettings.bak.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Copy-Item -LiteralPath $LocalSettings -Destination $bak -Force
    [System.IO.File]::WriteAllText($LocalSettings, $newContent.TrimEnd() + "`r`n", $Utf8Bom)
    Write-DeployLog "login_monitor.settings.ps1: исправлены WinRM-строки без `$ (резервная копия: $bak)"
    return $true
}

function Sync-RdpMonitorSettingsWinRmInboundBlock {
    param([string]$LocalSettings)
    if (-not (Test-Path -LiteralPath $LocalSettings)) { return $false }
    if (-not (Test-RdpMonitorSettingsNeedsWinRmInboundBlock -SettingsPath $LocalSettings)) {
        return $false
    }

    $c = Get-RdpMonitorSettingsRaw -Path $LocalSettings
    $linesToAdd = [System.Collections.Generic.List[string]]::new()
    [void]$linesToAdd.Add('# --- WinRM inbound (Enter-PSSession): обязательный блок (добавлено Deploy-LoginMonitor) ---')
    foreach ($def in Get-RdpMonitorWinRmInboundSettingDefinitions) {
        if ($c -notmatch $def.Pattern) {
            [void]$linesToAdd.Add($def.Line)
        }
    }
    if ($linesToAdd.Count -le 1) { return $false }

    $bak = "$LocalSettings.bak.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Copy-Item -LiteralPath $LocalSettings -Destination $bak -Force
    Write-DeployLog "Добавление WinRM inbound блока в login_monitor.settings.ps1; резервная копия: $bak"

    $block = ($linesToAdd -join "`r`n")
    $insertBefore = '(?m)^\s*#\s*---\s*Узкое исключение шумовых сетевых логонов'
    if ($c -match $insertBefore) {
        $newContent = [regex]::Replace($c, $insertBefore, ($block + "`r`n`r`n" + '$0'), 1)
    } else {
        $newContent = ($c.TrimEnd() + "`r`n`r`n" + $block + "`r`n")
    }
    [System.IO.File]::WriteAllText($LocalSettings, $newContent.TrimEnd() + "`r`n", $Utf8Bom)
    Write-DeployLog ("login_monitor.settings.ps1: WinRM inbound — добавлено строк: {0}" -f ($linesToAdd.Count - 1))
    return $true
}

function Get-RdpMonitorWinRmOperationalLogStatus {
    try {
        $log = Get-WinEvent -ListLog 'Microsoft-Windows-WinRM/Operational' -ErrorAction Stop
        if ($null -eq $log) {
            return 'not-found'
        }
        $enabled = $false
        try { $enabled = [bool]$log.IsEnabled } catch { $enabled = $false }
        if ($enabled) {
            return 'available-enabled'
        }
        return 'available-disabled'
    } catch {
        return 'not-found'
    }
}

function Ensure-RdpMonitorWinRmOperationalLogEnabled {
    $status = Get-RdpMonitorWinRmOperationalLogStatus
    if ($status -eq 'available-enabled') { return $true }
    if ($status -eq 'not-found') {
        Write-DeployLog "WinRM Operational журнал: не найден/недоступен, авто-включение невозможно."
        return $false
    }

    $wevtutilExe = Join-Path $env:SystemRoot 'System32\wevtutil.exe'
    if (-not (Test-Path -LiteralPath $wevtutilExe)) {
        Write-DeployLog "WinRM Operational журнал: wevtutil.exe не найден, авто-включение невозможно."
        return $false
    }

    try {
        $runEa = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'SilentlyContinue'
            $out = & $wevtutilExe sl 'Microsoft-Windows-WinRM/Operational' /e:true 2>&1
            foreach ($line in @($out)) {
                if ($null -ne $line -and "$line".Trim().Length -gt 0) {
                    Write-DeployLog "wevtutil sl WinRM/Operational: $line"
                }
            }
        } finally {
            $ErrorActionPreference = $runEa
        }
    } catch {
        Write-DeployLog "WinRM Operational журнал: ошибка авто-включения ($($_.Exception.Message))."
    }

    $after = Get-RdpMonitorWinRmOperationalLogStatus
    if ($after -eq 'available-enabled') {
        Write-DeployLog "WinRM Operational журнал: успешно включён deploy-скриптом."
        return $true
    }
    Write-DeployLog "WinRM Operational журнал: после попытки включения остаётся отключён/недоступен."
    return $false
}

function Sync-RdpMonitorSettingsHeartbeatInterval {
    param(
        [string]$LocalSettings,
        [int]$TargetSeconds = 14400
    )

    if (-not (Test-Path -LiteralPath $LocalSettings)) { return $false }

    $c = Get-RdpMonitorSettingsRaw -Path $LocalSettings
    if ([string]::IsNullOrWhiteSpace($c)) { return $false }

    if ($c -match '(?m)^\s*\$HeartbeatInterval\s*=\s*(\d+)') {
        $current = [int]$Matches[1]
        if ($current -eq $TargetSeconds) { return $false }
        $bak = "$LocalSettings.bak.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        Copy-Item -LiteralPath $LocalSettings -Destination $bak -Force
        $newContent = [regex]::Replace(
            $c,
            '(?m)^(\s*\$HeartbeatInterval\s*=\s*)\d+',
            "`${1}$TargetSeconds"
        )
        Write-DeployLog "login_monitor.settings.ps1: HeartbeatInterval $current → $TargetSeconds с (резервная копия: $bak)"
    } else {
        $bak = "$LocalSettings.bak.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        Copy-Item -LiteralPath $LocalSettings -Destination $bak -Force
        $block = @(
            '# --- Heartbeat SAC (agent.heartbeat): интервал в секундах; 14400 = 4 ч ---'
            "`$HeartbeatInterval = $TargetSeconds"
        ) -join "`r`n"
        $insertBeforeInventory = '(?m)^\s*#\s*---\s*Инвентаризация железа'
        if ($c -match $insertBeforeInventory) {
            $newContent = [regex]::Replace($c, $insertBeforeInventory, ($block + "`r`n`r`n" + '$0'), 1)
        } else {
            $newContent = ($c.TrimEnd() + "`r`n`r`n" + $block + "`r`n")
        }
        Write-DeployLog "login_monitor.settings.ps1: добавлен `$HeartbeatInterval = $TargetSeconds (резервная копия: $bak)"
    }

    [System.IO.File]::WriteAllText($LocalSettings, $newContent.TrimEnd() + "`r`n", $Utf8Bom)
    return $true
}

function Invoke-RdpMonitorSettingsPostPatches {
    param([string]$LocalSettings)
    if (-not (Test-Path -LiteralPath $LocalSettings)) { return $false }
    $changed = $false
    if (Update-RdpMonitorSettingsServerDisplayNameHintIfMissing -LocalSettings $LocalSettings) { $changed = $true }
    if (Sync-RdpMonitorSettingsDailyReportPatches -LocalSettings $LocalSettings) { $changed = $true }
    if (Sync-RdpMonitorSettingsExchangeNoisePatches -LocalSettings $LocalSettings) { $changed = $true }
    if (Repair-RdpMonitorSettingsWinRmLinesIfInvalid -LocalSettings $LocalSettings) { $changed = $true }
    if (Sync-RdpMonitorSettingsWinRmInboundBlock -LocalSettings $LocalSettings) { $changed = $true }
    if (Sync-RdpMonitorSettingsMaxBackupDaysIfMissing -LocalSettings $LocalSettings) { $changed = $true }
    if (Sync-RdpMonitorSettingsGetInventoryIfMissing -LocalSettings $LocalSettings) { $changed = $true }
    return $changed
}

function Test-RdpMonitorSettingsNeedsMaxBackupDays {
    param([string]$SettingsPath)
    if (-not (Test-Path -LiteralPath $SettingsPath)) { return $false }
    $c = Get-RdpMonitorSettingsRaw -Path $SettingsPath
    if ([string]::IsNullOrWhiteSpace($c)) { return $true }
    return ($c -notmatch '(?m)^\s*\$MaxBackupDays\s*=')
}

function Sync-RdpMonitorSettingsMaxBackupDaysIfMissing {
    param([string]$LocalSettings)

    if (-not (Test-RdpMonitorSettingsNeedsMaxBackupDays -SettingsPath $LocalSettings)) {
        return $false
    }

    $c = Get-RdpMonitorSettingsRaw -Path $LocalSettings
    $block = @(
        '# --- Ротация login_monitor.log и хранение бэкапов (Logs\Backup\LoginLog_*.bak) ---'
        '# $LogRotationHour = 0'
        '# $LogRotationMinute = 0'
        '$MaxBackupDays = 31'
    ) -join "`r`n"

    $bak = "$LocalSettings.bak.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    if (Test-Path -LiteralPath $LocalSettings) {
        Copy-Item -LiteralPath $LocalSettings -Destination $bak -Force
        Write-DeployLog "Добавление `$MaxBackupDays в login_monitor.settings.ps1; резервная копия: $bak"
    } else {
        Write-DeployLog "Создание login_monitor.settings.ps1 с `$MaxBackupDays = 31"
    }

    $insertBefore4740 = '(?m)^\s*#\s*---\s*Блокировка учётной записи AD'
    if (-not [string]::IsNullOrWhiteSpace($c) -and $c -match $insertBefore4740) {
        $newContent = [regex]::Replace($c, $insertBefore4740, ($block + "`r`n`r`n" + '$0'), 1)
    } elseif (-not [string]::IsNullOrWhiteSpace($c)) {
        $newContent = ($c.TrimEnd() + "`r`n`r`n" + $block + "`r`n")
    } else {
        $newContent = ($block + "`r`n")
    }

    [System.IO.File]::WriteAllText($LocalSettings, $newContent.TrimEnd() + "`r`n", $Utf8Bom)
    Write-DeployLog "login_monitor.settings.ps1: добавлен `$MaxBackupDays = 31"
    return $true
}

function Test-RdpMonitorSettingsNeedsGetInventory {
    param([string]$SettingsPath)
    if (-not (Test-Path -LiteralPath $SettingsPath)) { return $false }
    $c = Get-RdpMonitorSettingsRaw -Path $SettingsPath
    if ([string]::IsNullOrWhiteSpace($c)) { return $true }
    return ($c -notmatch '(?m)^\s*\$GetInventory\s*=')
}

function Sync-RdpMonitorSettingsGetInventoryIfMissing {
    param([string]$LocalSettings)

    if (-not (Test-RdpMonitorSettingsNeedsGetInventory -SettingsPath $LocalSettings)) {
        return $false
    }

    $c = Get-RdpMonitorSettingsRaw -Path $LocalSettings
    $block = @(
        '# --- Инвентаризация железа/ПО для SAC (agent.inventory, раз в 12 ч) ---'
        '$GetInventory = $true'
    ) -join "`r`n"

    $bak = "$LocalSettings.bak.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    if (Test-Path -LiteralPath $LocalSettings) {
        Copy-Item -LiteralPath $LocalSettings -Destination $bak -Force
        Write-DeployLog "Добавление `$GetInventory в login_monitor.settings.ps1; резервная копия: $bak"
    } else {
        Write-DeployLog "Создание login_monitor.settings.ps1 с `$GetInventory = `$true"
    }

    $insertAfterDaily = '(?m)^(\s*\$DailyReportEnabled\s*=.*)$'
    if (-not [string]::IsNullOrWhiteSpace($c) -and $c -match $insertAfterDaily) {
        $newContent = [regex]::Replace($c, $insertAfterDaily, ('$1' + "`r`n`r`n" + $block), 1)
    } elseif (-not [string]::IsNullOrWhiteSpace($c)) {
        $newContent = ($c.TrimEnd() + "`r`n`r`n" + $block + "`r`n")
    } else {
        $newContent = ($block + "`r`n")
    }

    [System.IO.File]::WriteAllText($LocalSettings, $newContent.TrimEnd() + "`r`n", $Utf8Bom)
    Write-DeployLog 'login_monitor.settings.ps1: добавлен $GetInventory = $true'
    return $true
}

function Update-RdpMonitorSettingsServerDisplayNameHintIfMissing {
    param([string]$LocalSettings)
    if (-not (Test-Path -LiteralPath $LocalSettings)) { return $false }
    if (-not (Test-RdpMonitorSettingsNeedsServerDisplayNameHint -SettingsPath $LocalSettings)) {
        return $false
    }

    $c = Get-RdpMonitorSettingsRaw -Path $LocalSettings
    if ([string]::IsNullOrWhiteSpace($c)) { return $false }

    $hostLabel = if ([string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) { 'New-PC' } else { $env:COMPUTERNAME.Trim() }
    $hintBlock = @(
        '# --- Подпись сервера в Telegram и SAC (host.display_name); раскомментируйте при необходимости ---'
        "# `$ServerDisplayName = '$hostLabel'"
        '# --- Явный IPv4 хоста для SAC (опционально; иначе автоопределение) ---'
        '# $ServerIPv4 = '''
    ) -join "`r`n"

    $bak = "$LocalSettings.bak.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Copy-Item -LiteralPath $LocalSettings -Destination $bak -Force
    Write-DeployLog "Добавление закомментированного `$ServerDisplayName в login_monitor.settings.ps1; резервная копия: $bak"

    $insertBefore = '(?m)^\s*#\s*---\s*Security Alert Center'
    if ($c -match $insertBefore) {
        $newContent = [regex]::Replace($c, $insertBefore, ($hintBlock + "`r`n`r`n" + '$0'), 1)
    } else {
        $newContent = ($c.TrimEnd() + "`r`n`r`n" + $hintBlock + "`r`n")
    }
    [System.IO.File]::WriteAllText($LocalSettings, $newContent.TrimEnd() + "`r`n", $Utf8Bom)
    Write-DeployLog "login_monitor.settings.ps1: добавлена подсказка # `$ServerDisplayName = '$hostLabel'"
    return $true
}

function Get-RdpMonitorSacBlockFromExample {
    param([string]$ExamplePath)
    if (-not (Test-Path -LiteralPath $ExamplePath)) { return $null }
    $ex = Get-RdpMonitorSettingsRaw -Path $ExamplePath
    if ([string]::IsNullOrWhiteSpace($ex)) { return $null }
    if ($ex -match '(?ms)(#\s*---\s*Security Alert Center.*?)(?=\r?\n#\s*---|\z)') {
        return $Matches[1].TrimEnd()
    }
    return @(
        '# --- Security Alert Center (SAC) ---'
        '$UseSAC = ''fallback'''
        '$SacUrl = ''https://sac.kalinamall.ru'''
        '$SacApiKey = ''sac_CHANGE_ME'''
    ) -join "`r`n"
}

function Sync-RdpMonitorUseSacFallbackMode {
    param([string]$LocalSettings)

    if (-not (Test-Path -LiteralPath $LocalSettings)) { return $false }
    $c = Get-RdpMonitorSettingsRaw -Path $LocalSettings
    if ([string]::IsNullOrWhiteSpace($c)) { return $false }
    if ($c -match '(?m)^\s*\$UseSAC\s*=\s*[''"]fallback[''"]') { return $false }
    if ($c -notmatch '(?m)^\s*\$UseSAC\s*=') { return $false }

    $newContent = [regex]::Replace(
        $c,
        '(?m)^(\s*\$UseSAC\s*=\s*)[''"][^''"]+[''"]',
        '$1''fallback'''
    )
    if ($newContent -eq $c) { return $false }

    $bak = "$LocalSettings.bak.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Copy-Item -LiteralPath $LocalSettings -Destination $bak -Force
    [System.IO.File]::WriteAllText($LocalSettings, $newContent.TrimEnd() + "`r`n", $Utf8Bom)
    Write-DeployLog "login_monitor.settings.ps1: UseSAC переключён на fallback (резервная копия: $bak)."
    return $true
}

function Update-RdpMonitorSettingsSacBlockIfMissing {
    param(
        [string]$LocalSettings,
        [string]$ExampleOnShare
    )
    if (-not (Test-Path -LiteralPath $LocalSettings)) { return $false }

    $c = Get-RdpMonitorSettingsRaw -Path $LocalSettings
    if ([string]::IsNullOrWhiteSpace($c)) { return $false }

    if ($c -match '(?m)^\s*\$UseSAC\s*=' -and $c -match '(?m)^\s*\$SacApiKey\s*=\s*[''"]sac_[^''"]+[''"]') {
        if ($c -notmatch '(?m)^\s*\$UseSAC\s*=\s*[''"]off[''"]') {
            Write-DeployLog "login_monitor.settings.ps1: блок SAC уже задан, файл не меняем."
            return $false
        }
    }

    $sacBlock = Get-RdpMonitorSacBlockFromExample -ExamplePath $ExampleOnShare
    if ([string]::IsNullOrWhiteSpace($sacBlock)) {
        Write-DeployLog "Предупреждение: не удалось извлечь блок SAC из example — пропуск patch settings."
        return $false
    }

    $bak = "$LocalSettings.bak.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Copy-Item -LiteralPath $LocalSettings -Destination $bak -Force
    Write-DeployLog "Добавление блока SAC (UseSAC=fallback) в login_monitor.settings.ps1; резервная копия: $bak"

    if ($c -match '(?m)^\s*\$UseSAC\s*=') {
        $c = [regex]::Replace($c, '(?m)^\s*\$UseSAC\s*=.*$', '')
        $c = [regex]::Replace($c, '(?m)^\s*\$SacUrl\s*=.*$', '')
        $c = [regex]::Replace($c, '(?m)^\s*\$SacApiKey\s*=.*$', '')
        $c = [regex]::Replace($c, '(?m)^\s*\$SacSpoolDir\s*=.*$', '')
        $c = [regex]::Replace($c, '(?m)^\s*\$SacTimeoutSec\s*=.*$', '')
        $c = [regex]::Replace($c, '(?m)^\s*\$SacTlsSkipVerify\s*=.*$', '')
        $c = [regex]::Replace($c, '(?m)^\s*\$SacFallbackFailures\s*=.*$', '')
    }

    $newContent = ($c.TrimEnd() + "`r`n`r`n" + $sacBlock + "`r`n").TrimEnd() + "`r`n"
    [System.IO.File]::WriteAllText($LocalSettings, $newContent, $Utf8Bom)
    Write-DeployLog "login_monitor.settings.ps1: добавлен блок SAC (UseSAC=fallback из example на шаре)."
    return $true
}

function Sync-RdpMonitorSettingsFromShare {
    param(
        [string]$ExampleOnShare,
        [string]$LocalSettings
    )
    if (-not (Test-Path -LiteralPath $ExampleOnShare)) {
        Write-DeployLog "Предупреждение: на шаре нет login_monitor.settings.example.ps1 — настройки SAC/Telegram не применены."
        return
    }

    $needsCreate = -not (Test-Path -LiteralPath $LocalSettings)
    $needsBootstrap = $needsCreate -or (Test-RdpMonitorSettingsNeedsSacBootstrap -SettingsPath $LocalSettings)

    if (-not $needsBootstrap) {
        Write-DeployLog "login_monitor.settings.ps1: SAC уже настроен, файл не перезаписываем."
        Invoke-RdpMonitorSettingsPostPatches -LocalSettings $LocalSettings | Out-Null
        return
    }

    if (-not (Test-Path -LiteralPath $InstallRoot)) {
        New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
    }

    if ($needsCreate) {
        Write-DeployLog "Создан login_monitor.settings.ps1 из example (Telegram + SAC fallback)."
        Copy-Item -LiteralPath $ExampleOnShare -Destination $LocalSettings -Force
        Invoke-RdpMonitorSettingsPostPatches -LocalSettings $LocalSettings | Out-Null
        return
    }

    if (Update-RdpMonitorSettingsSacBlockIfMissing -LocalSettings $LocalSettings -ExampleOnShare $ExampleOnShare) {
        Invoke-RdpMonitorSettingsPostPatches -LocalSettings $LocalSettings | Out-Null
        return
    }

    $bak = "$LocalSettings.bak.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Copy-Item -LiteralPath $LocalSettings -Destination $bak -Force
    Write-DeployLog "Апгрейд settings: резервная копия $bak, применяем example с шары."
    Copy-Item -LiteralPath $ExampleOnShare -Destination $LocalSettings -Force
    Invoke-RdpMonitorSettingsPostPatches -LocalSettings $LocalSettings | Out-Null
}

function Stop-RdpLoginMonitorMainProcesses {
    param([int]$GracefulWaitSec = 35)

    $canonical = [System.IO.Path]::GetFullPath($LocalScript)
    if (-not (Test-RdpMonitorMainProcessRunning -CanonicalScript $canonical)) {
        Write-DeployLog "Монитор не запущен — остановка не требуется."
        return
    }

    Write-DeployLog "Graceful stop: запись restart.request (mode=stop), без дочернего PowerShell."
    Set-RdpMonitorRestartRequestFromDeploy -Mode 'stop' -Reason 'deploy'

    $deadline = (Get-Date).AddSeconds($GracefulWaitSec)
    while ((Get-Date) -lt $deadline) {
        if (-not (Test-RdpMonitorMainProcessRunning -CanonicalScript $canonical)) {
            Write-DeployLog "Монитор завершился gracefully (до $($GracefulWaitSec) с)."
            return
        }
        Start-Sleep -Seconds 1
    }

    Write-DeployLog "Таймаут graceful stop — принудительная остановка оставшихся процессов монитора."
    try {
        $procs = Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe' OR Name = 'pwsh.exe'" -ErrorAction Stop
        foreach ($proc in $procs) {
            $cl = [string]$proc.CommandLine
            if ($cl -notmatch 'Login_Monitor\.ps1') { continue }
            if (Test-CommandLineIsWatchdog -CommandLine $cl) { continue }
            $sp = Get-ScriptPathFromCommandLine -CommandLine $cl
            if ($null -eq $sp) { continue }
            if ([System.IO.Path]::GetFullPath($sp) -ne $canonical) { continue }
            if ([int]$proc.ProcessId -eq $PID) { continue }
            Write-DeployLog "Stop-Process -Force PID $($proc.ProcessId) (fallback)."
            Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-DeployLog "Предупреждение при принудительной остановке: $($_.Exception.Message)"
    }
}

function Convert-RdpMonitorDeployTaskExecutionTimeLimitValue {
    param($Limit)

    if ($null -eq $Limit) { return $null }
    if ($Limit -is [TimeSpan]) { return $Limit }

    $text = [string]$Limit
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    $t = $text.Trim()
    if ($t -eq 'PT0S') { return [TimeSpan]::Zero }

    try {
        return [System.Xml.XmlConvert]::ToTimeSpan($t)
    } catch { }

    try {
        return [TimeSpan]::Parse($t)
    } catch { }

    return $null
}

function Test-RdpMonitorDeployTaskExecutionLimitUnlimitedValue {
    param($Limit)

    $normalized = Convert-RdpMonitorDeployTaskExecutionTimeLimitValue -Limit $Limit
    if ($null -eq $normalized) { return $false }
    if ($normalized.Ticks -le 0) { return $true }
    if ($normalized.TotalDays -ge 999) { return $true }
    return $false
}

function Get-RdpMonitorDeployTaskExecutionTimeLimitLabelFromResolved {
    param($Resolved)

    if ($null -eq $Resolved) { return '(null)' }
    if ($Resolved.Source -eq 'missing') { return '(task missing)' }
    $limit = Convert-RdpMonitorDeployTaskExecutionTimeLimitValue -Limit $Resolved.Limit
    if ($null -eq $limit) { return '(null)' }
    if ($limit.Ticks -le 0) { return 'PT0S' }
    return $limit.ToString()
}

function Test-RdpMonitorDeployTaskQueryReady {
    return [bool](Get-Command Get-RdpMonitorScheduledTaskExecutionTimeLimitResolved -ErrorAction SilentlyContinue)
}

function Publish-RdpMonitorDeployTaskQueryFunctionsToScriptScope {
    foreach ($name in @(
            'Get-RdpMonitorSchtasksExe',
            'Get-RdpMonitorScheduledTaskXmlDocument',
            'Test-RdpMonitorScheduledTaskExistsViaSchtasks',
            'Convert-RdpMonitorScheduledTaskExecutionTimeLimitText',
            'Get-RdpMonitorScheduledTaskExecutionTimeLimitFromDocument',
            'Get-RdpMonitorScheduledTaskActionFromDocument',
            'Test-RdpMonitorScheduledTaskExecutionTimeLimitUnlimitedValue',
            'Get-RdpMonitorScheduledTaskExecutionTimeLimitResolved',
            'Test-RdpMonitorScheduledTaskExecutionTimeLimitUnlimited',
            'Test-RdpMonitorScheduledTaskNeedsUnlimitedExecutionTimeLimit',
            'Get-RdpMonitorScheduledTaskExecutionTimeLimitLabel',
            'Test-RdpMonitorScheduledTaskActionMatchesViaSchtasks'
        )) {
        $cmd = Get-Command -Name $name -ErrorAction SilentlyContinue
        if ($null -ne $cmd -and $cmd.CommandType -eq 'Function') {
            Set-Item -Path "function:script:$name" -Value $cmd.ScriptBlock
        }
    }
}

function Import-RdpMonitorDeployTaskQueryModuleAtPath {
    param(
        [Parameter(Mandatory = $true)][string]$Candidate
    )

    if (-not (Test-Path -LiteralPath $Candidate)) { return $false }

    $loadPath = $Candidate
    $tempCopy = $null
    try {
        if ($Candidate.StartsWith('\\')) {
            $tempCopy = Join-Path $env:TEMP ("rdp-taskquery-{0}.ps1" -f [guid]::NewGuid().ToString('N'))
            Copy-Item -LiteralPath $Candidate -Destination $tempCopy -Force
            $loadPath = $tempCopy
        }
        . $loadPath
        if (Test-RdpMonitorDeployTaskQueryReady) {
            Publish-RdpMonitorDeployTaskQueryFunctionsToScriptScope
            return $true
        }
        Write-DeployLog "Предупреждение: $Candidate загружен, но функции TaskQuery недоступны — пробуем следующий источник."
    } catch {
        Write-DeployLog "Предупреждение: не удалось загрузить $Candidate — $($_.Exception.Message)"
    } finally {
        if ($null -ne $tempCopy -and (Test-Path -LiteralPath $tempCopy)) {
            Remove-Item -LiteralPath $tempCopy -Force -ErrorAction SilentlyContinue
        }
    }
    return $false
}

function Import-RdpMonitorDeployTaskQueryModule {
    param([string]$ShareRoot = '')

    $candidates = [System.Collections.Generic.List[string]]::new()
    $installCandidate = Join-Path $InstallRoot 'RdpMonitor-TaskQuery.ps1'
    $candidates.Add($installCandidate) | Out-Null

    $deployScriptPath = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($deployScriptPath)) { $deployScriptPath = $MyInvocation.MyCommand.Path }
    if (-not [string]::IsNullOrWhiteSpace($deployScriptPath)) {
        $deployCandidate = Join-Path (Split-Path -Parent $deployScriptPath) 'RdpMonitor-TaskQuery.ps1'
        if ($deployCandidate -ne $installCandidate) {
            $candidates.Add($deployCandidate) | Out-Null
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($ShareRoot)) {
        $shareCandidate = Join-Path $ShareRoot 'RdpMonitor-TaskQuery.ps1'
        if ($shareCandidate -ne $installCandidate -and -not ($candidates -contains $shareCandidate)) {
            $candidates.Add($shareCandidate) | Out-Null
        }
    }

    foreach ($candidate in @($candidates)) {
        if (Import-RdpMonitorDeployTaskQueryModuleAtPath -Candidate $candidate) {
            return $true
        }
    }
    return $false
}

function Initialize-RdpMonitorDeployTaskQuery {
    param([string]$ShareRoot = '')

    if (Test-RdpMonitorDeployTaskQueryReady) {
        return $true
    }

    $loaded = $false
    if (Import-RdpMonitorDeployTaskQueryModule -ShareRoot $ShareRoot) {
        $loaded = $true
    } else {
        Write-DeployLog "RdpMonitor-TaskQuery.ps1 недоступен — deploy использует встроенную проверку schtasks /XML."
        . $script:RdpMonitorDeployTaskQueryInlineScript
        $loaded = (Test-RdpMonitorDeployTaskQueryReady)
    }

    if ($loaded) {
        Publish-RdpMonitorDeployTaskQueryFunctionsToScriptScope
    }
    return $loaded
}

$script:RdpMonitorDeployTaskQueryInlineScript = {
    function Get-RdpMonitorSchtasksExe {
        return Join-Path $env:SystemRoot 'System32\schtasks.exe'
    }

    function Get-RdpMonitorScheduledTaskXmlDocument {
        param([Parameter(Mandatory = $true)][string]$TaskName)
        $exe = Get-RdpMonitorSchtasksExe
        $prevEa = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'SilentlyContinue'
            $raw = & $exe /Query /TN $TaskName /XML 2>&1
            if ($LASTEXITCODE -ne 0) { return $null }
            $text = ($raw | Out-String).Trim()
            if ([string]::IsNullOrWhiteSpace($text)) { return $null }
            if ($text -notmatch '(?s)<Task\b') { return $null }
            return [xml]$text
        } catch {
            return $null
        } finally {
            $ErrorActionPreference = $prevEa
        }
    }

    function Convert-RdpMonitorScheduledTaskExecutionTimeLimitText {
        param([string]$LimitText)
        if ([string]::IsNullOrWhiteSpace($LimitText)) { return $null }
        $t = $LimitText.Trim()
        if ($t -eq 'PT0S') { return [TimeSpan]::Zero }
        try { return [System.Xml.XmlConvert]::ToTimeSpan($t) } catch { return $null }
    }

    function Get-RdpMonitorScheduledTaskExecutionTimeLimitFromDocument {
        param([xml]$Doc)
        if ($null -eq $Doc) { return $null }
        $ns = New-Object System.Xml.XmlNamespaceManager($Doc.NameTable)
        $ns.AddNamespace('t', 'http://schemas.microsoft.com/windows/2004/02/mit/task')
        $node = $Doc.SelectSingleNode('//t:Settings/t:ExecutionTimeLimit', $ns)
        if ($null -eq $node) {
            $node = $Doc.SelectSingleNode('//*[local-name()="Settings"]/*[local-name()="ExecutionTimeLimit"]')
        }
        if ($null -eq $node -or [string]::IsNullOrWhiteSpace($node.InnerText)) { return $null }
        return Convert-RdpMonitorScheduledTaskExecutionTimeLimitText -LimitText $node.InnerText.Trim()
    }

    function Test-RdpMonitorScheduledTaskExecutionTimeLimitUnlimitedValue {
        param($Limit)
        if ($null -eq $Limit -or $Limit -isnot [TimeSpan]) { return $false }
        if ($Limit.Ticks -le 0) { return $true }
        if ($Limit.TotalDays -ge 999) { return $true }
        return $false
    }

    function Get-RdpMonitorScheduledTaskExecutionTimeLimitResolved {
        param([Parameter(Mandatory = $true)][string]$TaskName)
        try {
            $limit = (Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop | Select-Object -First 1).Settings.ExecutionTimeLimit
            return [pscustomobject]@{ Limit = $limit; Source = 'Get-ScheduledTask' }
        } catch { }
        $doc = Get-RdpMonitorScheduledTaskXmlDocument -TaskName $TaskName
        if ($null -eq $doc) {
            return [pscustomobject]@{ Limit = $null; Source = 'missing' }
        }
        $limit = Get-RdpMonitorScheduledTaskExecutionTimeLimitFromDocument -Doc $doc
        return [pscustomobject]@{ Limit = $limit; Source = 'schtasks-xml' }
    }

    function Test-RdpMonitorScheduledTaskNeedsUnlimitedExecutionTimeLimit {
        param([Parameter(Mandatory = $true)][string]$TaskName)
        $resolved = Get-RdpMonitorScheduledTaskExecutionTimeLimitResolved -TaskName $TaskName
        if ($resolved.Source -eq 'missing') { return $true }
        return (-not (Test-RdpMonitorScheduledTaskExecutionTimeLimitUnlimitedValue -Limit $resolved.Limit))
    }

    function Get-RdpMonitorScheduledTaskExecutionTimeLimitLabel {
        param([Parameter(Mandatory = $true)][string]$TaskName)
        $resolved = Get-RdpMonitorScheduledTaskExecutionTimeLimitResolved -TaskName $TaskName
        if ($resolved.Source -eq 'missing') { return '(task missing)' }
        $limit = $resolved.Limit
        if ($null -eq $limit) { return '(null)' }
        if ($limit -is [TimeSpan] -and $limit.Ticks -le 0) { return 'PT0S' }
        return $limit.ToString()
    }
}

function Test-RdpMonitorDeployMainTaskNeedsUnlimitedExecutionTime {
    param(
        [string]$TaskName = 'RDP-Login-Monitor',
        [string]$ShareRoot = ''
    )
    if (-not (Initialize-RdpMonitorDeployTaskQuery -ShareRoot $ShareRoot)) { return $true }
    $resolved = Get-RdpMonitorScheduledTaskExecutionTimeLimitResolved -TaskName $TaskName
    if ($resolved.Source -eq 'missing') { return $true }
    return (-not (Test-RdpMonitorDeployTaskExecutionLimitUnlimitedValue -Limit $resolved.Limit))
}

function Get-RdpMonitorDeployMainTaskExecutionTimeLimitLabel {
    param(
        [string]$TaskName = 'RDP-Login-Monitor',
        [string]$ShareRoot = ''
    )
    if (-not (Initialize-RdpMonitorDeployTaskQuery -ShareRoot $ShareRoot)) {
        return '(TaskQuery not loaded)'
    }
    $resolved = Get-RdpMonitorScheduledTaskExecutionTimeLimitResolved -TaskName $TaskName
    return (Get-RdpMonitorDeployTaskExecutionTimeLimitLabelFromResolved -Resolved $resolved)
}

function Write-RdpMonitorDeployScheduledTaskVerification {
    param(
        [string]$TaskName = 'RDP-Login-Monitor',
        [string]$ShareRoot = ''
    )

    if (-not (Initialize-RdpMonitorDeployTaskQuery -ShareRoot $ShareRoot)) {
        Write-DeployLog "ПРЕДУПРЕЖДЕНИЕ: проверка ExecutionTimeLimit недоступна (TaskQuery не инициализирован)."
        return $false
    }

    $resolved = Get-RdpMonitorScheduledTaskExecutionTimeLimitResolved -TaskName $TaskName
    if ($resolved.Source -eq 'schtasks-xml') {
        Write-DeployLog "Задача ${TaskName}: ExecutionTimeLimit проверен через schtasks /XML (Get-ScheduledTask недоступен)."
    }

    if (-not (Test-RdpMonitorDeployTaskExecutionLimitUnlimitedValue -Limit $resolved.Limit)) {
        $label = Get-RdpMonitorDeployTaskExecutionTimeLimitLabelFromResolved -Resolved $resolved
        Write-DeployLog "ПРЕДУПРЕЖДЕНИЕ: $TaskName ExecutionTimeLimit=$label — ожидался PT0S (без лимита). Проверьте InstallTasks и права администратора."
        return $false
    }
    Write-DeployLog "Задача ${TaskName}: ExecutionTimeLimit=PT0S (без лимита) — OK."
    return $true
}

function Invoke-RdpMonitorDeploySacVersionNotice {
    if (-not (Test-Path -LiteralPath $LocalScript)) {
        Write-DeployLog "SAC deploy notice: Login_Monitor.ps1 не найден — пропуск."
        return
    }
    $settingsLocal = Join-Path $InstallRoot 'login_monitor.settings.ps1'
    if (-not (Test-Path -LiteralPath $settingsLocal)) {
        Write-DeployLog "SAC deploy notice: login_monitor.settings.ps1 отсутствует — пропуск."
        return
    }

    $outLog = Join-Path $InstallRoot 'Logs\deploy_sac_notice_stdout.log'
    $errLog = Join-Path $InstallRoot 'Logs\deploy_sac_notice_stderr.log'
    $noticeArgs = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $LocalScript, '-SendDeploySacNotice'
    )
    $p = Start-Process -FilePath $PsExe -ArgumentList $noticeArgs -Wait -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $outLog -RedirectStandardError $errLog
    if ($p.ExitCode -eq 0) {
        Write-DeployLog "SAC: версия агента передана сразу после деплоя (SendDeploySacNotice)."
        return
    }

    Write-DeployLog "Предупреждение: SendDeploySacNotice завершился с кодом $($p.ExitCode) — SAC обновится при старте монитора (agent.lifecycle)."
    foreach ($pair in @(@($outLog, 'stdout'), @($errLog, 'stderr'))) {
        $lp = $pair[0]
        $lbl = $pair[1]
        if (Test-Path -LiteralPath $lp) {
            $tail = Get-Content -LiteralPath $lp -Tail 20 -ErrorAction SilentlyContinue
            if ($tail) {
                Write-DeployLog "SendDeploySacNotice $lbl (хвост): $($tail -join ' | ')"
            }
        }
    }
}

# --- main ---
if ($env:RDP_DEPLOY_FUNCTIONS_ONLY -eq '1') { return }

try {
    $shareRoot = Resolve-SourceShareRoot
    $sourceScript = Join-Path $shareRoot $ScriptName
    $sourceVersionFile = Join-Path $shareRoot $VersionFileName

    Write-DeployLog "Deploy: корень дистрибутива: $shareRoot"

    $settingsLocal = Join-Path $InstallRoot 'login_monitor.settings.ps1'
    $settingsExampleShare = Join-Path $shareRoot 'login_monitor.settings.example.ps1'

    if (-not (Test-Path -LiteralPath $sourceScript)) {
        Write-DeployLog "ОШИБКА: на шаре нет файла: $sourceScript"
        exit 0
    }
    if (-not (Test-Path -LiteralPath $sourceVersionFile)) {
        Write-DeployLog "ОШИБКА: на шаре нет version.txt: $sourceVersionFile (добавьте одну строку с версией, как в Login_Monitor.ps1)."
        exit 0
    }

    $shareVerRaw = Read-VersionLineFromFile -Path $sourceVersionFile
    if ([string]::IsNullOrWhiteSpace($shareVerRaw)) {
        Write-DeployLog "ОШИБКА: version.txt пустой или не читается: $sourceVersionFile"
        exit 0
    }

    $localVerRaw = Get-LocalDeployedVersion
    Write-DeployLog "Версия на шаре: $shareVerRaw; локально установлено: $(if ($localVerRaw) { $localVerRaw } else { '(нет)' })."

    if (-not (Test-Path -LiteralPath (Join-Path $shareRoot $SacClientName))) {
        Write-DeployLog "ОШИБКА: на шаре отсутствует $SacClientName — выполните update-rdp-monitor.ps1 на сервере публикации."
    }

    [void](Initialize-RdpMonitorDeployTaskQuery -ShareRoot $shareRoot)

    $needsSettingsBootstrap = Test-RdpMonitorSettingsNeedsSacBootstrap -SettingsPath $settingsLocal
    $needsDisplayNameHint = Test-RdpMonitorSettingsNeedsServerDisplayNameHint -SettingsPath $settingsLocal
    $needsDailyReportHint = Test-RdpMonitorSettingsNeedsDailyReportHint -SettingsPath $settingsLocal
    $needsDailyReportRepair = Test-RdpMonitorSettingsHasInvalidDailyReportAssignment -SettingsPath $settingsLocal
    $needsExchangeNoisePatch = Test-RdpMonitorSettingsNeedsExchangeNoisePatch -SettingsPath $settingsLocal
    $needsWinRmInboundBlock = Test-RdpMonitorSettingsNeedsWinRmInboundBlock -SettingsPath $settingsLocal
    $needsBundleSync = Test-RdpMonitorDeployBundleNeedsSync -ShareRoot $shareRoot
    $needsTaskExecutionLimitFix = Test-RdpMonitorDeployMainTaskNeedsUnlimitedExecutionTime -ShareRoot $shareRoot
    $needsSacBootstrap = $needsSettingsBootstrap -or $needsBundleSync -or $needsDisplayNameHint -or $needsDailyReportHint -or $needsDailyReportRepair -or $needsExchangeNoisePatch -or $needsWinRmInboundBlock -or $needsTaskExecutionLimitFix

    if (Test-RdpMonitorExchangeServerRole) {
        Write-DeployLog "Обнаружена роль Exchange — при необходимости допишем WinRM/4624 noise settings в login_monitor.settings.ps1."
    }
    $winRmLogStatus = Get-RdpMonitorWinRmOperationalLogStatus
    switch ($winRmLogStatus) {
        'available-enabled' { Write-DeployLog "WinRM Operational журнал: доступен и включён (Microsoft-Windows-WinRM/Operational)." }
        'available-disabled' { Write-DeployLog "WinRM Operational журнал: найден, но отключён. Включите канал в Event Viewer (Applications and Services Logs -> Microsoft -> Windows -> WinRM -> Operational)." }
        default { Write-DeployLog "WinRM Operational журнал: не найден/недоступен. Проверьте компонент WinRM и канал Microsoft-Windows-WinRM/Operational." }
    }
    if ($winRmLogStatus -ne 'available-enabled') {
        Ensure-RdpMonitorWinRmOperationalLogEnabled | Out-Null
    }

    $cmp = Compare-VersionStrings -Left $shareVerRaw -Right $localVerRaw
    $isScriptVersionUpgrade = ($null -ne $cmp -and $cmp -gt 0 -and -not [string]::IsNullOrWhiteSpace($localVerRaw))
    if ($null -ne $cmp) {
        if ($cmp -eq 0) {
            if (-not $needsSacBootstrap) {
                Write-DeployLog "Актуально, копирование не требуется."
                exit 0
            }
            if ($needsBundleSync) {
                Write-DeployLog "Версия совпадает ($shareVerRaw), но пакет файлов (Login_Monitor/Sac-Client) отличается — продолжаем деплой."
            } elseif ($needsSettingsBootstrap) {
                Write-DeployLog "Версия совпадает ($shareVerRaw), но нужна донастройка SAC в settings — продолжаем деплой."
            } elseif ($needsDisplayNameHint) {
                Write-DeployLog "Версия совпадает ($shareVerRaw), но нет подсказки `$ServerDisplayName в settings — продолжаем деплой."
            } elseif ($needsDailyReportHint) {
                Write-DeployLog "Версия совпадает ($shareVerRaw), но нет `$DailyReportEnabled в settings — продолжаем деплой."
            } elseif ($needsDailyReportRepair) {
                Write-DeployLog "Версия совпадает ($shareVerRaw), но в settings некорректно задан `$DailyReportEnabled (= true/false без `$) — продолжаем деплой."
            } elseif ($needsExchangeNoisePatch) {
                Write-DeployLog "Версия совпадает ($shareVerRaw), но на Exchange не хватает noise settings (WinRM/4624) — продолжаем деплой."
            } elseif ($needsWinRmInboundBlock) {
                Write-DeployLog "Версия совпадает ($shareVerRaw), но в settings отсутствует обязательный блок WinRM inbound — продолжаем деплой."
            } elseif ($needsTaskExecutionLimitFix) {
                $limitLabel = Get-RdpMonitorDeployMainTaskExecutionTimeLimitLabel -ShareRoot $shareRoot
                Write-DeployLog "Версия совпадает ($shareVerRaw), но RDP-Login-Monitor имеет ExecutionTimeLimit=$limitLabel — перерегистрируем задачи (InstallTasks)."
            }
        }
        if ($cmp -lt 0 -and -not $AllowDowngrade) {
            Write-DeployLog "На шаре версия старше локальной — пропуск (используйте -AllowDowngrade для отката)."
            exit 0
        }
    }

    if (-not (Test-Path -LiteralPath $InstallRoot)) {
        if ($WhatIf) {
            Write-DeployLog "[WhatIf] Создать каталог $InstallRoot"
        } else {
            New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
        }
    }

    if ($WhatIf) {
        if ($needsSettingsBootstrap) {
            Write-DeployLog "[WhatIf] Донастроить login_monitor.settings.ps1 (SAC fallback из example)."
        }
        if ($needsBundleSync) {
            Write-DeployLog "[WhatIf] Синхронизировать пакет: $($DeployBundleFiles -join ', ')."
        }
        Write-DeployLog "[WhatIf] InstallTasks; версия $shareVerRaw"
        exit 0
    }

    if (-not (Test-DeployRunningElevated)) {
        Write-DeployLog "ОШИБКА: запустите Deploy из повышенной консоли PowerShell («Запуск от имени администратора»). Без этого дочерний Login_Monitor.ps1 -InstallTasks завершится с кодом 1 (нет прав на регистрацию задач)."
        exit 0
    }

    Stop-RdpLoginMonitorMainProcesses

    Copy-RdpMonitorDeployBundle -ShareRoot $shareRoot

    Sync-RdpMonitorSettingsFromShare -ExampleOnShare $settingsExampleShare -LocalSettings $settingsLocal

    # При каждом deploy выравниваем HeartbeatInterval в settings (14400 с = 4 ч), не только при bump версии.
    Sync-RdpMonitorSettingsHeartbeatInterval -LocalSettings $settingsLocal | Out-Null

    if ($isScriptVersionUpgrade) {
        Sync-RdpMonitorUseSacFallbackMode -LocalSettings $settingsLocal | Out-Null
    }

    $installArgs = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $LocalScript, '-InstallTasks', '-SkipImmediateMainRun'
    )
    $instOut = Join-Path $InstallRoot "Logs\deploy_installtasks_stdout.log"
    $instErr = Join-Path $InstallRoot "Logs\deploy_installtasks_stderr.log"
    $p = Start-Process -FilePath $PsExe -ArgumentList $installArgs -Wait -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $instOut -RedirectStandardError $instErr
    if ($p.ExitCode -ne 0) {
        Write-DeployLog "Предупреждение: InstallTasks завершился с кодом $($p.ExitCode)."
        foreach ($pair in @(@($instOut, 'stdout'), @($instErr, 'stderr'))) {
            $lp = $pair[0]
            $lbl = $pair[1]
            if (Test-Path -LiteralPath $lp) {
                $tail = Get-Content -LiteralPath $lp -Tail 40 -ErrorAction SilentlyContinue
                if ($tail) {
                    Write-DeployLog "InstallTasks $lbl (хвост): $($tail -join ' | ')"
                }
            }
        }
        Write-DeployLog "Подсказка: полный вывод в Logs\deploy_installtasks_*.log; также см. login_monitor.log за это время."
    } else {
        Write-DeployLog "InstallTasks выполнен (код 0)."
    }

    [void](Write-RdpMonitorDeployScheduledTaskVerification -ShareRoot $shareRoot)

    [System.IO.File]::WriteAllText($VersionStampPath, "$shareVerRaw`r`n", $Utf8Bom)
    Write-DeployLog "Записана метка версии: $VersionStampPath"

    $updStamp = Get-Date -Format "dd.MM.yyyy HH:mm:ss"
    $updMarker = @(
        "Version=$shareVerRaw"
        "UpdatedAt=$updStamp"
        "PendingStartupNotice=1"
    ) -join "`r`n"
    [System.IO.File]::WriteAllText($DeployUpdateMarkerPath, "$updMarker`r`n", $Utf8Bom)
    Write-DeployLog "Записана метка обновления: $DeployUpdateMarkerPath (Version=$shareVerRaw; UpdatedAt=$updStamp)."

    Invoke-RdpMonitorDeploySacVersionNotice

    if (-not $SkipStartMonitorAfterUpdate) {
        $canonical = [System.IO.Path]::GetFullPath($LocalScript)
        if (Test-RdpMonitorMainProcessRunning -CanonicalScript $canonical) {
            Write-DeployLog "Монитор уже запущен — повторный старт не выполняем."
        } else {
            $taskName = 'RDP-Login-Monitor'
            $schtasksExe = Join-Path $env:SystemRoot 'System32\schtasks.exe'
            $runEa = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'SilentlyContinue'
                $runOut = & $schtasksExe /Run /TN $taskName 2>&1
                foreach ($line in @($runOut)) {
                    if ($null -ne $line -and "$line".Trim().Length -gt 0) {
                        Write-DeployLog "schtasks /Run $taskName : $line"
                    }
                }
            } finally {
                $ErrorActionPreference = $runEa
            }
            Write-DeployLog "Запуск монитора через schtasks /Run ($taskName)."
        }
    } else {
        Write-DeployLog "Запуск монитора пропущен (-SkipStartMonitorAfterUpdate); поднимется при следующей загрузке или watchdog."
    }

    exit 0
} catch {
    Write-DeployLog "КРИТИЧЕСКАЯ ОШИБКА: $($_.Exception.Message)"
    exit 0
}
