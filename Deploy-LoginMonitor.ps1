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
      \\dc\share\RDP-login-monitor\version.txt         — одна строка, например: 1.3.0
      \\dc\share\RDP-login-monitor\Deploy-LoginMonitor.ps1

    Если Deploy-LoginMonitor.ps1 запускают с этой шары, параметр -SourceShareRoot можно не указывать —
    корень шары берётся из расположения этого файла.

.NOTES
    Лог: C:\ProgramData\RDP-login-monitor\Logs\deploy.log
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

$InstallRoot = [System.IO.Path]::GetFullPath("$env:ProgramData\RDP-login-monitor")
$LocalScript = Join-Path $InstallRoot "Login_Monitor.ps1"
$VersionStampPath = Join-Path $InstallRoot "deployed_version.txt"
$DeployLogPath = Join-Path $InstallRoot "Logs\deploy.log"
$ScriptName = "Login_Monitor.ps1"
$VersionFileName = "version.txt"
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
            if ($ln -match '^\s*\$ScriptVersion\s*=\s*["'']([0-9]+(?:\.[0-9]+){0,3})["'']') {
                return $Matches[1]
            }
        }
    } catch { }

    return $null
}

function Normalize-VersionOrNull {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $t = $Text.Trim() -replace '^v', ''
    try {
        return [version]$t
    } catch {
        return $null
    }
}

function Compare-VersionStrings {
    param([string]$Left, [string]$Right)
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

function Stop-RdpLoginMonitorMainProcesses {
    $canonical = [System.IO.Path]::GetFullPath($LocalScript)
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
            Write-DeployLog "Останавливаю процесс монитора PID $($proc.ProcessId) перед обновлением файла."
            Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-DeployLog "Предупреждение при остановке монитора: $($_.Exception.Message)"
    }
}

# --- main ---
try {
    $shareRoot = Resolve-SourceShareRoot
    $sourceScript = Join-Path $shareRoot $ScriptName
    $sourceVersionFile = Join-Path $shareRoot $VersionFileName

    Write-DeployLog "Deploy: корень дистрибутива: $shareRoot"

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

    $cmp = Compare-VersionStrings -Left $shareVerRaw -Right $localVerRaw
    if ($null -ne $cmp) {
        if ($cmp -eq 0) {
            Write-DeployLog "Актуально, копирование не требуется."
            exit 0
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
        Write-DeployLog "[WhatIf] Скопировать $sourceScript -> $LocalScript; InstallTasks; версия $shareVerRaw"
        exit 0
    }

    Stop-RdpLoginMonitorMainProcesses

    Copy-Item -LiteralPath $sourceScript -Destination $LocalScript -Force
    Write-DeployLog "Файл скопирован: $LocalScript"

    $installArgs = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $LocalScript, '-InstallTasks'
    )
    $p = Start-Process -FilePath $PsExe -ArgumentList $installArgs -Wait -PassThru -WindowStyle Hidden
    if ($p.ExitCode -ne 0) {
        Write-DeployLog "Предупреждение: InstallTasks завершился с кодом $($p.ExitCode)."
    } else {
        Write-DeployLog "InstallTasks выполнен (код 0)."
    }

    [System.IO.File]::WriteAllText($VersionStampPath, "$shareVerRaw`r`n", $Utf8Bom)
    Write-DeployLog "Записана метка версии: $VersionStampPath"

    if (-not $SkipStartMonitorAfterUpdate) {
        Start-Process -FilePath $PsExe -ArgumentList @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $LocalScript
        ) -WindowStyle Hidden
        Write-DeployLog "Запущен процесс монитора (новый файл)."
    } else {
        Write-DeployLog "Запуск монитора пропущен (-SkipStartMonitorAfterUpdate); поднимется при следующей загрузке или watchdog."
    }

    exit 0
} catch {
    Write-DeployLog "КРИТИЧЕСКАЯ ОШИБКА: $($_.Exception.Message)"
    exit 0
}
