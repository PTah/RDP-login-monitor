# Rewrite cross-repo URLs in tracked docs/config for the target Git host.
# Usage: .\scripts\Rewrite-GitHostUrls.ps1 github|origin|example-admin
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('github', 'origin', 'example-admin')]
    [string]$Target
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

switch ($Target) {
    'github' {
        $Base = 'https://github.com/PTah'
        $BlobSuffix = '/blob/main'
    }
    'origin' {
        $Base = 'https://github.com/PapaTramp'
        $BlobSuffix = '/src/branch/main'
    }
    'example-admin' {
        $Base = 'https://git.example-admin.ru/PTah'
        $BlobSuffix = '/src/branch/main'
    }
}

$BaseHost = $Base -replace '^https://', ''

$patterns = @(
    @{ From = 'https://github.com/PTah/([^)/''"\s]+)/blob/main/'; To = "$Base/`$1$BlobSuffix/" }
    @{ From = 'https://github.com/PTah/([^)/''"\s]+)/src/branch/main/'; To = "$Base/`$1$BlobSuffix/" }
    @{ From = 'https://github.com/PTah/([^)/''"\s]+)/src/branch/main/'; To = "$Base/`$1$BlobSuffix/" }
    @{ From = 'https://github.com/PTah/'; To = "$Base/" }
    @{ From = 'https://github.com/PTah/'; To = "$Base/" }
    @{ From = 'https://github.com/PTah/'; To = "$Base/" }
    @{ From = 'github.com/PTah/'; To = "$BaseHost/" }
    @{ From = 'github.com/PTah/'; To = "$BaseHost/" }
    @{ From = 'github.com/PTah/'; To = "$BaseHost/" }
)

$extensions = @('*.md', '*.json', '*.service', '*.example', '*.sh', '*.ps1', '*.yml', '*.yaml')
$files = git ls-files $extensions 2>$null | Where-Object { $_ -and (Test-Path $_) }

foreach ($file in $files) {
    $content = [System.IO.File]::ReadAllText((Join-Path $Root $file))
    $updated = $content
    foreach ($p in $patterns) {
        $updated = [regex]::Replace($updated, $p.From, $p.To)
    }
    if ($updated -ne $content) {
        [System.IO.File]::WriteAllText((Join-Path $Root $file), $updated, [System.Text.UTF8Encoding]::new($false))
        Write-Output "updated: $file"
    }
}

Write-Output "Rewrite-GitHostUrls: target=$Target base=$Base"
