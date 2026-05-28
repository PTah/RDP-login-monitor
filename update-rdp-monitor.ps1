<#
.SYNOPSIS
    Obnovlyaet klon RDP-login-monitor s git.kalinamall.ru i kopiruet dist na NETLOGON.
.DESCRIPTION
    Dlya servera publikatsii (napr. DC3). Remote: git.kalinamall.ru (kalinamall).
    Posle fetch: vsegda reset --hard na kalinamall/main (bez merge), zatem clean -fd.
    Kopiruyutsya: polnyj spisok v Docs/deploy-netlogon-publish.md.
.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\soft\update-rdp-monitor.ps1
.EXAMPLE
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\soft\update-rdp-monitor.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$RepoPath = 'C:\Soft\Git\RDP-login-monitor',
    [string]$NetlogonDest = '\\b26\NETLOGON\RDP-login-monitor',
    [string]$GitUrl = 'https://git.kalinamall.ru/PapaTramp/RDP-login-monitor.git',
    [string]$GitBranch = 'main',
    [string]$LogFile = 'C:\soft\Logs\update-rdp-monitor.log',
    [switch]$SkipGitClean
)

$ErrorActionPreference = 'Stop'
$DistFiles = @(
    'Login_Monitor.ps1',
    'Sac-Client.ps1',
    'version.txt',
    'Deploy-LoginMonitor.ps1',
    'Restart-RdpLoginMonitor.ps1',
    'Exchange-MailSecurity.ps1',
    'Notify-Common.ps1',
    'Install-DomainMonitors.ps1',
    'Deploy-DomainMonitors.ps1',
    'exchange_monitor.settings.example.ps1',
    'login_monitor.settings.example.ps1'
)

function Write-UpdateLog {
    param([string]$Message)
    $line = '[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Write-Host $line
    $dir = Split-Path -Parent $LogFile
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $utf8Bom = New-Object System.Text.UTF8Encoding $true
    [System.IO.File]::AppendAllText($LogFile, $line + [Environment]::NewLine, $utf8Bom)
}

function Invoke-GitCommand {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [string]$WorkingDirectory = $RepoPath
    )
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        Push-Location -LiteralPath $WorkingDirectory
        # stderr git (progress) ne dolzhen lomat skript v PowerShell 5.1
        $raw = & git @Arguments 2>&1
        $code = $LASTEXITCODE
    } finally {
        Pop-Location
        $ErrorActionPreference = $prevEap
    }
    $lines = @()
    foreach ($item in @($raw)) {
        if ($null -eq $item) { continue }
        if ($item -is [System.Management.Automation.ErrorRecord]) {
            $lines += $item.ToString()
        } else {
            $lines += [string]$item
        }
    }
    foreach ($line in $lines) {
        if ($line.Length -gt 0) {
            Write-UpdateLog "git: $line"
        }
    }
    if ($code -ne 0) {
        throw ("git {0} failed (exit {1})" -f ($Arguments -join ' '), $code)
    }
    return $lines
}

function Get-GitShortHead {
    $lines = Invoke-GitCommand -Arguments @('rev-parse', '--short', 'HEAD')
    foreach ($line in $lines) {
        $t = $line.Trim()
        if ($t -match '^[0-9a-f]{7,40}$') {
            return $t
        }
    }
    return ($lines -join ' ').Trim()
}

function Ensure-GitAvailable {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        throw 'git.exe not found in PATH. Install Git for Windows.'
    }
}

function Ensure-GitRepository {
    $gitDir = Join-Path $RepoPath '.git'
    if (-not (Test-Path -LiteralPath $gitDir)) {
        throw "Not a git repo (no .git): $RepoPath. Clone first: git clone $GitUrl `"$RepoPath`""
    }
}

function Get-ConfiguredGitRemoteName {
    $names = @(Invoke-GitCommand -Arguments @('remote') | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if ($names.Count -eq 0) { return $null }
    if ('kalinamall' -in $names) { return 'kalinamall' }
    foreach ($n in $names) {
        $url = (& git -C $RepoPath remote get-url $n 2>$null)
        if ($url -match 'git\.kalinamall\.ru') { return $n }
    }
    if ('origin' -in $names) { return 'origin' }
    return $names[0]
}

function Ensure-GitKalinamallRemote {
    $name = Get-ConfiguredGitRemoteName
    if ($null -ne $name) {
        $url = (& git -C $RepoPath remote get-url $name 2>$null)
        if ($url -match 'git\.kalinamall\.ru') {
            Write-UpdateLog "Using remote: $name ($url)"
            return $name
        }
        Write-UpdateLog "Remote $name is not kalinamall ($url); adding kalinamall -> $GitUrl"
    } else {
        Write-UpdateLog "No remotes; adding kalinamall -> $GitUrl"
    }
    if ('kalinamall' -in @(& git -C $RepoPath remote 2>$null)) {
        Invoke-GitCommand -Arguments @('remote', 'set-url', 'kalinamall', $GitUrl)
        return 'kalinamall'
    }
    Invoke-GitCommand -Arguments @('remote', 'add', 'kalinamall', $GitUrl)
    return 'kalinamall'
}

function Update-Repository {
    Ensure-GitRepository
    $remote = Ensure-GitKalinamallRemote
    Invoke-GitCommand -Arguments @('fetch', '--prune', $remote, $GitBranch)
    $upstream = "${remote}/${GitBranch}"

    $dirty = @(Invoke-GitCommand -Arguments @('status', '--porcelain') | Where-Object { "$_".Trim().Length -gt 0 })
    if ($dirty.Count -gt 0) {
        Write-UpdateLog "WARN: discarding $($dirty.Count) local change(s) on publish clone (reset --hard + clean)"
        foreach ($d in $dirty) {
            Write-UpdateLog "  $d"
        }
    }

    $mergeHead = Join-Path $RepoPath '.git\MERGE_HEAD'
    if (Test-Path -LiteralPath $mergeHead) {
        Write-UpdateLog 'WARN: incomplete merge — aborting before sync'
        Invoke-GitCommand -Arguments @('merge', '--abort')
    }

    Invoke-GitCommand -Arguments @('reset', '--hard', $upstream)
    if (-not $SkipGitClean) {
        Invoke-GitCommand -Arguments @('clean', '-fd')
    }

    $remoteHead = (Invoke-GitCommand -Arguments @('rev-parse', '--short', $upstream) | Where-Object { $_ -match '^[0-9a-f]{7,40}$' } | Select-Object -First 1)
    $head = Get-GitShortHead
    Write-UpdateLog "HEAD: $head (target $upstream = $remoteHead)"
}

function Copy-FileToNetlogon {
    param(
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][string]$DestPath
    )
    if ($SourcePath -like '*.ps1') {
        $raw = [System.IO.File]::ReadAllBytes($SourcePath)
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        $text = $utf8NoBom.GetString($raw)
        if ($text.Length -gt 0 -and [int][char]$text[0] -eq 0xFEFF) {
            $text = $text.Substring(1)
        }
        $utf8Bom = New-Object System.Text.UTF8Encoding $true
        [System.IO.File]::WriteAllText($DestPath, $text, $utf8Bom)
        return
    }
    Copy-Item -LiteralPath $SourcePath -Destination $DestPath -Force
}

function Publish-DistributionFiles {
    if (-not (Test-Path -LiteralPath $NetlogonDest)) {
        if ($PSCmdlet.ShouldProcess($NetlogonDest, 'Create directory')) {
            New-Item -ItemType Directory -Path $NetlogonDest -Force | Out-Null
            Write-UpdateLog "Created: $NetlogonDest"
        }
    }
    $repoVer = Join-Path $RepoPath 'version.txt'
    if (-not (Test-Path -LiteralPath $repoVer)) {
        throw "Missing version.txt in repo: $repoVer"
    }
    $expectedVer = (Get-Content -LiteralPath $repoVer -Raw).Trim()
    Write-UpdateLog "Repo version.txt: $expectedVer"

    foreach ($name in $DistFiles) {
        $src = Join-Path $RepoPath $name
        if (-not (Test-Path -LiteralPath $src)) {
            throw "Missing in repo: $src"
        }
        $dst = Join-Path $NetlogonDest $name
        if ($PSCmdlet.ShouldProcess($dst, "Copy from $src")) {
            Copy-FileToNetlogon -SourcePath $src -DestPath $dst
            Write-UpdateLog "Copied: $name -> $NetlogonDest"
        }
    }
    $verFile = Join-Path $NetlogonDest 'version.txt'
    if (Test-Path -LiteralPath $verFile) {
        $ver = (Get-Content -LiteralPath $verFile -Raw).Trim()
        Write-UpdateLog "NETLOGON version: $ver"
        if ($ver -ne $expectedVer) {
            Write-UpdateLog "ERROR: NETLOGON version mismatch (expected $expectedVer)"
            throw "NETLOGON version.txt is $ver, expected $expectedVer"
        }
    }
}

try {
    Write-UpdateLog '=== RDP-login-monitor: git pull -> NETLOGON ==='
    Ensure-GitAvailable
    Update-Repository
    Publish-DistributionFiles
    Write-UpdateLog '=== Done ==='
    exit 0
} catch {
    Write-UpdateLog "ERROR: $($_.Exception.Message)"
    exit 1
}
