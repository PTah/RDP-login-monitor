#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [string]$TaskName = "RDP-Login-Monitor-Deploy",
    [string]$DeployScriptPath = "\\B26\NETLOGON\RDP-login-monitor\Deploy-LoginMonitor.ps1",
    [ValidateRange(5, 1440)][int]$RepeatMinutes = 60,
    [switch]$RunNow
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($DeployScriptPath)) {
    throw "DeployScriptPath не задан."
}

$psExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
if (-not (Test-Path -LiteralPath $psExe)) {
    throw "Не найден powershell.exe по пути: $psExe"
}

$taskCmd = "`"$psExe`" -NoProfile -ExecutionPolicy Bypass -File `"$DeployScriptPath`""
$schtasksExe = Join-Path $env:SystemRoot "System32\schtasks.exe"

Write-Host "Создаю/обновляю задачу: $TaskName" -ForegroundColor Cyan
Write-Host "Команда: $taskCmd" -ForegroundColor DarkGray
Write-Host "Периодичность: каждые $RepeatMinutes мин." -ForegroundColor DarkGray

& $schtasksExe /Create /F /TN $TaskName /RU SYSTEM /RL HIGHEST /SC MINUTE /MO $RepeatMinutes /TR $taskCmd | Out-Host

if ($LASTEXITCODE -ne 0) {
    throw "schtasks /Create вернул код $LASTEXITCODE"
}

Write-Host "Задача создана/обновлена: $TaskName" -ForegroundColor Green

if ($RunNow) {
    Write-Host "Запускаю задачу немедленно..." -ForegroundColor Cyan
    & $schtasksExe /Run /TN $TaskName | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "schtasks /Run вернул код $LASTEXITCODE"
    }
}

Write-Host "Готово." -ForegroundColor Green
