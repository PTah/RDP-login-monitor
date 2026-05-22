<#
.SYNOPSIS
    Deploy domain monitor scripts (Exchange / AD) from share to ProgramData.
.PARAMETER Target
    Exchange - Exchange-MailSecurity.ps1 + Notify-Common.ps1; Ad - reserved.
#>
[CmdletBinding()]
param(
    [ValidateSet('Exchange', 'Ad')]
    [Parameter(Mandatory = $true)]
    [string]$Target,
    [string]$SourceShareRoot = '',
    [switch]$WhatIf,
    [switch]$SkipInstallTasks,
    [switch]$AllowDowngrade
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$InstallRoot = [System.IO.Path]::GetFullPath("$env:ProgramData\RDP-login-monitor")
$VersionStampPath = Join-Path $InstallRoot 'deployed_domain_monitors_version.txt'
$DeployLogPath = Join-Path $InstallRoot 'Logs\deploy_domain_monitors.log'
$VersionFileName = 'version.txt'
$Utf8Bom = New-Object System.Text.UTF8Encoding $true
$PsExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"

$ExchangeFiles = @(
    'Exchange-MailSecurity.ps1',
    'Notify-Common.ps1',
    'Install-DomainMonitors.ps1'
)

function Write-DeployLog {
    param([string]$Message)
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - [$Target] $Message" + [Environment]::NewLine
    try {
        $dir = Split-Path $DeployLogPath -Parent
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        [System.IO.File]::AppendAllText($DeployLogPath, $line, $Utf8Bom)
    } catch { }
    Write-Host $line.TrimEnd("`r`n")
}

function Write-TextFileUtf8Bom {
    param([string]$Path, [string]$Text)
    [System.IO.File]::WriteAllText($Path, $Text, $Utf8Bom)
}

function Resolve-SourceShareRoot {
    if (-not [string]::IsNullOrWhiteSpace($SourceShareRoot)) {
        return [System.IO.Path]::GetFullPath($SourceShareRoot.TrimEnd('\'))
    }
    $here = $PSCommandPath
    if ([string]::IsNullOrWhiteSpace($here)) { $here = $MyInvocation.MyCommand.Path }
    if ([string]::IsNullOrWhiteSpace($here)) {
        throw 'Specify -SourceShareRoot or run this script by full UNC path to the .ps1 file on the share.'
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

function Compare-SemVerLike {
    param([string]$A, [string]$B)
    try {
        $va = [version]$A
        $vb = [version]$B
        return $va.CompareTo($vb)
    } catch {
        return [string]::Compare($A, $B, [StringComparison]::OrdinalIgnoreCase)
    }
}

$shareRoot = Resolve-SourceShareRoot
$filesToCopy = switch ($Target) {
    'Exchange' { $ExchangeFiles }
    'Ad' { throw 'Target Ad is not supported yet.' }
}

$sourceVersionFile = Join-Path $shareRoot $VersionFileName
if (-not (Test-Path -LiteralPath $sourceVersionFile)) {
    Write-DeployLog "ERROR: missing on share: $sourceVersionFile"
    exit 1
}

$shareVer = Read-VersionLineFromFile -Path $sourceVersionFile
$localVer = Read-VersionLineFromFile -Path $VersionStampPath
Write-DeployLog "Share version=$shareVer local stamp=$localVer"

if (-not [string]::IsNullOrWhiteSpace($localVer)) {
    $cmp = Compare-SemVerLike -A $shareVer -B $localVer
    if ($cmp -eq 0) {
        Write-DeployLog 'Version match - skip copy.'
        if (-not $SkipInstallTasks) {
            Write-DeployLog 'Running InstallTasks check...'
            if (-not $WhatIf) {
                & $PsExe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $InstallRoot 'Install-DomainMonitors.ps1') -Target $Target
            }
        }
        exit 0
    }
    if ($cmp -lt 0 -and -not $AllowDowngrade) {
        Write-DeployLog 'Share version older than local - skip (use -AllowDowngrade to force).'
        exit 0
    }
}

if (-not (Test-Path -LiteralPath $InstallRoot)) {
    if ($WhatIf) { Write-DeployLog "WhatIf: create $InstallRoot"; exit 0 }
    New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
}

foreach ($name in $filesToCopy) {
    $src = Join-Path $shareRoot $name
    $dst = Join-Path $InstallRoot $name
    if (-not (Test-Path -LiteralPath $src)) {
        Write-DeployLog "ERROR: missing on share: $name"
        exit 1
    }
    if ($WhatIf) {
        Write-DeployLog "WhatIf: copy $src -> $dst"
        continue
    }
    Copy-Item -LiteralPath $src -Destination $dst -Force
    Write-DeployLog "Copied: $name"
}

if (-not $WhatIf) {
    Write-TextFileUtf8Bom -Path $VersionStampPath -Text $shareVer
    if (-not $SkipInstallTasks) {
        $installer = Join-Path $InstallRoot 'Install-DomainMonitors.ps1'
        & $PsExe -NoProfile -ExecutionPolicy Bypass -File $installer -Target $Target
        if ($LASTEXITCODE -ne 0) {
            Write-DeployLog "Install-DomainMonitors exit code: $LASTEXITCODE"
            exit $LASTEXITCODE
        }
    }
}

Write-DeployLog 'Deploy-DomainMonitors finished.'
exit 0
