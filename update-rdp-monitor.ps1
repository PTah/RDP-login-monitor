<#
.SYNOPSIS
    Обновляет локальный клон RDP-login-monitor с git.kalinamall.ru и копирует дистрибутив на NETLOGON.
.DESCRIPTION
    Запуск на сервере с доступом к \\b26\NETLOGON (SYSVOL), например с правами администратора домена.
    Копируются: Login_Monitor.ps1, version.txt, Deploy-LoginMonitor.ps1.
.EXAMPLE
    C:\soft\update-rdp-monitor.ps1
.EXAMPLE
    C:\soft\update-rdp-monitor.ps1 -RepoPath 'C:\soft\Git\RDP-login-monitor' -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$RepoPath = 'C:\soft\Git\RDP-login-monitor',
    [string]$NetlogonDest = '\\b26\NETLOGON\RDP-login-monitor',
    [string]$GitRemote = 'kalinamall',
    [string]$GitBranch = 'main',
    [string]$LogFile = 'C:\soft\Logs\update-rdp-monitor.log'
)

$ErrorActionPreference = 'Stop'
$DistFiles = @('Login_Monitor.ps1', 'version.txt', 'Deploy-LoginMonitor.ps1')

function Write-UpdateLog {
    param([string]$Message)
    $line = '[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Write-Host $line
    $dir = Split-Path -Parent $LogFile
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8
}

function Ensure-GitAvailable {
    $git = Get-Command git -ErrorAction SilentlyContinue
    if (-not $git) {
        throw 'Git не найден в PATH. Установите Git for Windows или добавьте git.exe в PATH.'
    }
}

function Update-Repository {
    if (-not (Test-Path -LiteralPath (Join-Path $RepoPath '.git'))) {
        throw "Не найден git-репозиторий: $RepoPath (нет папки .git). Сначала выполните: git clone https://git.kalinamall.ru/PapaTramp/RDP-login-monitor.git `"$RepoPath`""
    }
    Push-Location -LiteralPath $RepoPath
    try {
        $remotes = @(git remote 2>&1)
        if ($GitRemote -notin $remotes) {
            if ('origin' -in $remotes) {
                Write-UpdateLog "Remote '$GitRemote' не найден, используется origin."
                $script:GitRemote = 'origin'
            } else {
                throw "Нет remote '$GitRemote'. Доступные: $($remotes -join ', '). Добавьте: git remote add kalinamall https://git.kalinamall.ru/PapaTramp/RDP-login-monitor.git"
            }
        }
        Write-UpdateLog "git fetch $GitRemote"
        git fetch $GitRemote 2>&1 | ForEach-Object { Write-UpdateLog $_ }
        Write-UpdateLog "git pull $GitRemote $GitBranch"
        git pull $GitRemote $GitBranch 2>&1 | ForEach-Object { Write-UpdateLog $_ }
        $head = (git rev-parse --short HEAD 2>&1)
        Write-UpdateLog "HEAD после pull: $head"
    } finally {
        Pop-Location
    }
}

function Publish-DistributionFiles {
    if (-not (Test-Path -LiteralPath $NetlogonDest)) {
        if ($PSCmdlet.ShouldProcess($NetlogonDest, 'Create directory')) {
            New-Item -ItemType Directory -Path $NetlogonDest -Force | Out-Null
            Write-UpdateLog "Создан каталог: $NetlogonDest"
        }
    }
    foreach ($name in $DistFiles) {
        $src = Join-Path $RepoPath $name
        if (-not (Test-Path -LiteralPath $src)) {
            throw "В репозитории нет файла: $src"
        }
        $dst = Join-Path $NetlogonDest $name
        if ($PSCmdlet.ShouldProcess($dst, "Copy from $src")) {
            Copy-Item -LiteralPath $src -Destination $dst -Force
            Write-UpdateLog "Скопировано: $name -> $NetlogonDest"
        }
    }
    $verFile = Join-Path $NetlogonDest 'version.txt'
    if (Test-Path -LiteralPath $verFile) {
        $ver = (Get-Content -LiteralPath $verFile -Raw).Trim()
        Write-UpdateLog "Версия на NETLOGON: $ver"
    }
}

try {
    Write-UpdateLog '=== Старт обновления RDP-login-monitor -> NETLOGON ==='
    Ensure-GitAvailable
    Update-Repository
    Publish-DistributionFiles
    Write-UpdateLog '=== Готово ==='
    exit 0
} catch {
    Write-UpdateLog "ОШИБКА: $($_.Exception.Message)"
    exit 1
}
