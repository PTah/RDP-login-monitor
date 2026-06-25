<#
.SYNOPSIS
    Graceful restart RDP Login Monitor без Stop-Process.
.DESCRIPTION
    settings — перечитать login_monitor.settings.ps1 в том же процессе PowerShell.
    recycle  — корректно завершить монитор и запустить новый процесс (после обновления Login_Monitor.ps1).
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File Restart-RdpLoginMonitor.ps1
    powershell -ExecutionPolicy Bypass -File Restart-RdpLoginMonitor.ps1 -Recycle
#>
[CmdletBinding()]
param(
    [switch]$Recycle
)

$ErrorActionPreference = 'Stop'
$installRoot = [System.IO.Path]::GetFullPath("$env:ProgramData\RDP-login-monitor")
$monitorScript = Join-Path $installRoot 'Login_Monitor.ps1'

if (-not (Test-Path -LiteralPath $monitorScript)) {
    Write-Error "Не найден: $monitorScript"
    exit 1
}

$args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $monitorScript, '-RequestRestart')
if ($Recycle) { $args += '-Recycle' }

& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" @args
exit $LASTEXITCODE
