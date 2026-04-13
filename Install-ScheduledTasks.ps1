#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Регистрирует в Планировщике заданий основной монитор и watchdog (как в README).
.DESCRIPTION
    Запускайте из повышенной PowerShell. Пути по умолчанию — D:\Soft\.
    Watchdog использует Watchdog_RDP_Monitor.ps1 из репозитория (проверка процесса и heartbeat).
#>
[CmdletBinding()]
param(
    [string]$InstallRoot = "D:\Soft",
    [string]$MainTaskName = "RDP Login Monitor",
    [string]$WatchdogTaskName = "RDP Login Monitor Watchdog",
    [int]$WatchdogRepeatMinutes = 5,
    [int]$MainStartupRandomDelayMinutes = 1,
    [int]$WatchdogStartupRandomDelayMinutes = 2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$LoginScriptPath = Join-Path $InstallRoot "Login_Monitor.ps1"
$WatchdogScriptPath = Join-Path $InstallRoot "Watchdog_RDP_Monitor.ps1"
$LogsDir = Join-Path $InstallRoot "Logs"

if (-not (Test-Path -LiteralPath $LoginScriptPath)) {
    throw "Не найден основной скрипт: $LoginScriptPath"
}
if (-not (Test-Path -LiteralPath $WatchdogScriptPath)) {
    throw "Не найден watchdog: $WatchdogScriptPath"
}
if (-not (Test-Path -LiteralPath $LogsDir)) {
    New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null
}

$principal = New-ScheduledTaskPrincipal `
    -UserId "NT AUTHORITY\SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

# --- Задание 1: основной монитор ---
$mainArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$LoginScriptPath`""
$mainAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument $mainArgs
$mainTrigger = New-ScheduledTaskTrigger -AtStartup -RandomDelay (New-TimeSpan -Minutes $MainStartupRandomDelayMinutes)
$mainSettings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew

Register-ScheduledTask `
    -TaskName $MainTaskName `
    -Action $mainAction `
    -Trigger $mainTrigger `
    -Principal $principal `
    -Settings $mainSettings `
    -Force | Out-Null

Write-Host "Создано задание: $MainTaskName" -ForegroundColor Cyan

# --- Задание 2: watchdog (старт + периодический запуск, как в README) ---
$wdArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$WatchdogScriptPath`""
$wdAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument $wdArgs
$wdTriggerStartup = New-ScheduledTaskTrigger -AtStartup -RandomDelay (New-TimeSpan -Minutes $WatchdogStartupRandomDelayMinutes)
$repeatDuration = New-TimeSpan -Days 3650
$anchor = (Get-Date).AddMinutes([Math]::Max(3, $WatchdogRepeatMinutes))
$wdTriggerRepeat = New-ScheduledTaskTrigger -Once -At $anchor `
    -RepetitionInterval (New-TimeSpan -Minutes $WatchdogRepeatMinutes) `
    -RepetitionDuration $repeatDuration

$wdSettings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew

Register-ScheduledTask `
    -TaskName $WatchdogTaskName `
    -Action $wdAction `
    -Trigger @($wdTriggerStartup, $wdTriggerRepeat) `
    -Principal $principal `
    -Settings $wdSettings `
    -Force | Out-Null

Write-Host "Создано задание: $WatchdogTaskName (триггеры: при старте ОС и каждые $WatchdogRepeatMinutes мин.)" -ForegroundColor Cyan
Write-Host "Готово. При необходимости сразу запустите: Start-ScheduledTask -TaskName '$MainTaskName'" -ForegroundColor Green
