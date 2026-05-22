<#
.SYNOPSIS
    Register scheduled tasks for domain monitors (Exchange; AD later).
.PARAMETER Target
    Exchange - Exchange-MailSecurity.ps1; Ad - reserved.
#>
[CmdletBinding()]
param(
    [ValidateSet('Exchange', 'Ad')]
    [Parameter(Mandatory = $true)]
    [string]$Target
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$InstallRoot = [System.IO.Path]::GetFullPath("$env:ProgramData\RDP-login-monitor")
$PsExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

function Test-RunningElevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -ne $id.User -and $id.User.Value -eq 'S-1-5-18') { return $true }
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-RunningElevated)) {
    throw 'Run Install-DomainMonitors.ps1 as Administrator.'
}

switch ($Target) {
    'Exchange' {
        $scriptPath = Join-Path $InstallRoot 'Exchange-MailSecurity.ps1'
        if (-not (Test-Path -LiteralPath $scriptPath)) {
            throw "Not found: $scriptPath"
        }
        $notifyPath = Join-Path $InstallRoot 'Notify-Common.ps1'
        if (-not (Test-Path -LiteralPath $notifyPath)) {
            throw "Not found: $notifyPath"
        }
        & $PsExe -NoProfile -ExecutionPolicy Bypass -File $scriptPath -InstallTasks
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        Write-Host 'Exchange: scheduled tasks registered.'
    }
    'Ad' {
        Write-Host 'AD-SecurityMonitor.ps1 is not implemented yet. Use -Target Exchange.'
        exit 1
    }
}

exit 0
