# Push main to a mirror remote with host-specific doc URLs, without leaving URL churn on main.
# Usage: .\scripts\Push-Mirror.ps1 github|origin|example-admin
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('github', 'origin', 'example-admin')]
    [string]$Target
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$remote = switch ($Target) {
    'github' { 'origin' }
    'origin' { 'origin' }
    'example-admin' { 'example-admin' }
}

git remote get-url $remote 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "remote not configured: $remote"
}

if ((git status --porcelain)) {
    throw 'working tree not clean; commit or stash first'
}

$before = (git rev-parse HEAD).Trim()
& "$PSScriptRoot\Rewrite-GitHostUrls.ps1" -Target $Target

if (-not (git status --porcelain)) {
    Write-Output "no URL changes for $Target; pushing as-is"
    git push $remote main
    exit 0
}

git add -A
git commit -m "chore(docs): sync repository URLs for ${Target} mirror"
git push $remote main
git reset --hard $before
Write-Output "pushed $remote with ${Target} URLs; local main reset to $before"
