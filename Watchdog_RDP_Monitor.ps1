<#
.SYNOPSIS
    Watchdog для Login_Monitor.ps1
.DESCRIPTION
    Проверяет, запущен ли основной скрипт Login_Monitor.ps1.
    Если нет — запускает его и пишет лог.
    Дополнительно проверяет heartbeat-файл и перезапускает скрипт, если heartbeat "протух".
#>

[CmdletBinding()]
param(
    [string]$MainScriptPath = "D:\Soft\Login_Monitor.ps1",
    [string]$HeartbeatFile = "D:\Soft\Logs\last_heartbeat.txt",
    [int]$HeartbeatStaleMinutes = 90,
    [string]$WatchdogLog = "D:\Soft\Logs\watchdog.log"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-WatchdogLog {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts - $Message"
    $dir = Split-Path -Parent $WatchdogLog
    if ($dir -and -not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    Add-Content -Path $WatchdogLog -Value $line -Encoding UTF8
}

function Get-MainScriptProcesses {
    try {
        $procs = Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe' OR Name = 'pwsh.exe'" -ErrorAction Stop
        return $procs | Where-Object { $_.CommandLine -and ($_.CommandLine -like "*$MainScriptPath*") }
    } catch {
        Write-WatchdogLog "Ошибка проверки процессов: $($_.Exception.Message)"
        return @()
    }
}

function Start-MainScript {
    if (-not (Test-Path $MainScriptPath)) {
        Write-WatchdogLog "Основной скрипт не найден: $MainScriptPath"
        return
    }
    $args = "-NoProfile -ExecutionPolicy Bypass -File `"$MainScriptPath`""
    Start-Process -FilePath "powershell.exe" -ArgumentList $args -WindowStyle Hidden | Out-Null
    Write-WatchdogLog "Основной скрипт запущен: $MainScriptPath"
}

function Stop-MainScript {
    $procs = Get-MainScriptProcesses
    foreach ($p in $procs) {
        try {
            Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop
            Write-WatchdogLog "Остановлен зависший экземпляр PID=$($p.ProcessId)"
        } catch {
            Write-WatchdogLog "Ошибка остановки PID=$($p.ProcessId): $($_.Exception.Message)"
        }
    }
}

function Is-HeartbeatStale {
    if (-not (Test-Path $HeartbeatFile)) {
        Write-WatchdogLog "Heartbeat файл отсутствует: $HeartbeatFile"
        return $true
    }
    try {
        $raw = (Get-Content $HeartbeatFile -ErrorAction Stop | Select-Object -First 1).Trim()
        if (-not $raw) { return $true }
        $hb = [datetime]::ParseExact($raw, "dd.MM.yyyy HH:mm:ss", $null)
        $age = (Get-Date) - $hb
        return ($age.TotalMinutes -gt $HeartbeatStaleMinutes)
    } catch {
        Write-WatchdogLog "Ошибка чтения heartbeat: $($_.Exception.Message)"
        return $true
    }
}

$running = Get-MainScriptProcesses
if (-not $running -or $running.Count -eq 0) {
    Write-WatchdogLog "Основной скрипт не запущен, выполняю старт."
    Start-MainScript
    exit 0
}

if (Is-HeartbeatStale) {
    Write-WatchdogLog "Heartbeat устарел, перезапускаю основной скрипт."
    Stop-MainScript
    Start-Sleep -Seconds 2
    Start-MainScript
} else {
    Write-WatchdogLog "Проверка пройдена: процесс запущен, heartbeat свежий."
}

